#!/usr/bin/env bash
# GitHub Actions runner 上校验 / 重签微信 Donut 云构建产出的 IPA。
# 用法: ci-sign.sh <ipa> <verify|resign>
# 说明: 云构建时已用 p12 + mobileprovision 签过名，默认只验签；resign 才会用 Secrets 重签。
set -euo pipefail

IPA="${1:?usage: ci-sign.sh <ipa> <verify|resign>}"
MODE="${2:-verify}"
PY="$(command -v python3 || command -v python)"
[ -n "$PY" ] || { echo "::error::需要 python3 或 python"; exit 1; }
T="${RUNNER_TEMP:-/tmp}"
WORK="$T/ipa-work"
EXPECTED_BUNDLE_ID="${EXPECTED_BUNDLE_ID:-com.jieli.bmstool}"
export EXPECTED_BUNDLE_ID
# Apple 自 2027-04 起要求上传到 App Store Connect 的 iOS/iPadOS App 部署目标 >= 15.0。
# 微信 Donut 云构建未暴露 iOS deployment target 配置（产物默认 13.0），
# 故在 resign 时把主 App Info.plist 的 MinimumOSVersion 提升到该值，再整体重新签名。
MIN_OS_VERSION="${MIN_OS_VERSION:-15.0}"
export MIN_OS_VERSION
# Guideline 2.5.19 整改：云构建默认放开 ATS (NSAllowsArbitraryLoads=true)。
# resign 时收紧为严格策略，避免「与外部平台服务器的不受控加密通信」这一加重项。
# 设为 'false' 可回退到云构建原值（仅用于排查 ATS 导致的网络异常）。
ATS_STRICT="${ATS_STRICT:-true}"
export ATS_STRICT

cleanup() {
  rm -f "$T/cert.p12" "$T/profile.mobileprovision" "$T/ent.tmp.plist" \
        "$T/ent.old.plist" "$T/ipa-tops.txt" "$T/sign-order.bin"
}
trap cleanup EXIT

fail() { echo "::error::$*" >&2; exit 1; }
note() { echo "::notice::$*"; }

# ---------- 通用结构校验（macOS / Linux 均可） ----------
inspect() {
"$PY" - "$IPA" <<'PY'
import os, sys, zipfile, plistlib
ipa = sys.argv[1]
expected = os.environ.get("EXPECTED_BUNDLE_ID", "com.jieli.bmstool")
rows, fails = [], []
with zipfile.ZipFile(ipa) as z:
    bad = z.testzip()
    if bad:
        fails.append("ZIP 损坏: %s" % bad)
    names = z.namelist()
    infos = [n for n in names
             if n.startswith("Payload/") and n.endswith(".app/Info.plist") and n.count("/") == 2]
    if len(infos) != 1:
        fails.append("Payload 下 .app/Info.plist 数量异常: %d" % len(infos))
        info, app = {}, None
    else:
        app = infos[0][:-len("Info.plist")]
        info = plistlib.loads(z.read(infos[0]))
        rows.append(("App 路径", app.rstrip("/")))
        for key, label in (("CFBundleIdentifier", "Bundle ID"),
                           ("CFBundleShortVersionString", "版本"),
                           ("CFBundleVersion", "Build 号"),
                           ("MinimumOSVersion", "最低系统")):
            rows.append((label, str(info.get(key, "<缺失>"))))
        min_req = os.environ.get("MIN_OS_VERSION", "15.0")
        try:
            def vnum(s):
                return tuple(int(x) for x in str(s).split("."))
            if vnum(info.get("MinimumOSVersion", "0")) < vnum(min_req):
                rows.append(("部署目标提示", "当前 %s 低于要求 %s，resign 将自动提升"
                             % (info.get("MinimumOSVersion"), min_req)))
        except ValueError:
            pass
        if info.get("CFBundleIdentifier") != expected:
            fails.append("Bundle ID 不符: %s != %s" % (info.get("CFBundleIdentifier"), expected))
        rows.append(("出口合规 ITSAppUsesNonExemptEncryption",
                     str(info.get("ITSAppUsesNonExemptEncryption", "<未设置>"))))
        usages = {k: v for k, v in info.items() if k.startswith("NS") and k.endswith("UsageDescription")}
        rows.append(("权限描述键数量", str(len(usages))))
        bad_desc = [k for k, v in usages.items()
                    if any(ord(c) > 127 for c in str(v)) or "Demo" in str(v) or "请前往" in str(v)]
        if bad_desc:
            fails.append("权限文案含中文模板/Demo: %s" % ", ".join(bad_desc))
        for rel, label, required in (("embedded.mobileprovision", "分发描述文件", True),
                                     ("_CodeSignature/CodeResources", "签名资源", True)):
            ok = (app + rel) in names
            rows.append((label, "存在" if ok else "缺失"))
            if required and not ok:
                fails.append("%s 缺失" % label)

lines = ["### IPA 结构校验", "", "| 项 | 值 |", "| --- | --- |"]
lines += ["| %s | %s |" % (k, str(v).replace("|", "\\|")) for k, v in rows]
lines += ["", "- 失败项：**%d**" % len(fails)]
if fails:
    lines += ["- " + f for f in fails]
out = "\n".join(lines) + "\n"
print(out)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as f:
        f.write(out)
if fails:
    for f in fails:
        print("::error::" + f)
    sys.exit(1)
PY
}

# ---------- macOS 专项：codesign 验签 + 描述文件解析 ----------
verify_macos() {
  local APP="$1"
  codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -20
  codesign -dv --verbose=4 "$APP" 2>&1 | grep -E 'Identifier=|Authority=|TeamIdentifier=|Signature=' || true
  security cms -D -i "$APP/embedded.mobileprovision" > "$T/profile.plist"
"$PY" - "$T/profile.plist" <<'PY'
import os, sys, plistlib, datetime
raw = open(sys.argv[1], "rb").read()
i = raw.find(b"<?xml")
if i < 0:
    i = raw.find(b"bplist00")
p = plistlib.loads(raw[i:] if i >= 0 else raw)
rows, fails = [], []
rows.append(("Profile 名称", p.get("Name", "<缺失>")))
rows.append(("Profile UUID", p.get("UUID", "<缺失>")))
rows.append(("TeamIdentifier", ", ".join(p.get("TeamIdentifier", []))))
exp = p.get("ExpirationDate")
now = datetime.datetime.now(datetime.timezone.utc)
if isinstance(exp, datetime.datetime):
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=datetime.timezone.utc)
    rows.append(("Profile 到期", exp.isoformat()))
    if exp <= now:
        fails.append("分发描述文件已过期: %s" % exp.isoformat())
else:
    fails.append("读取不到 ExpirationDate")
gta = p.get("Entitlements", {}).get("get-task-allow")
rows.append(("get-task-allow", str(gta)))
if gta is not False:
    fails.append("get-task-allow 应为 false（必须是 App Store 分发签名），实际为 %s" % gta)
prov_bid = p.get("Entitlements", {}).get("application-identifier", "")
rows.append(("application-identifier", prov_bid))
out = "\n".join(["### 签名 / 描述文件校验", "", "| 项 | 值 |", "| --- | --- |"] +
                ["| %s | %s |" % (k, str(v).replace("|", "\\|")) for k, v in rows] +
                ["", "- 失败项：**%d**" % len(fails)] + ["- " + f for f in fails]) + "\n"
print(out)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as f:
        f.write(out)
for f in fails:
    print("::error::" + f)
sys.exit(1 if fails else 0)
PY
}

# ---------- macOS 专项：用 Secrets 中的证书重签 ----------
resign_macos() {
  [ -n "${P12_BASE64:-}" ] || fail "resign 需要 Secret: P12_BASE64"
  [ -n "${P12_PASSWORD:-}" ] || fail "resign 需要 Secret: P12_PASSWORD"
  [ -n "${MOBILEPROVISION_BASE64:-}" ] || fail "resign 需要 Secret: MOBILEPROVISION_BASE64"

  local KEYCHAIN="$T/ios-sign.keychain-db"
  local KP
  KP="$("$PY" -c 'import secrets;print(secrets.token_urlsafe(24))')"

  "$PY" -c 'import base64,os,sys;open(sys.argv[1],"wb").write(base64.b64decode(os.environ["P12_BASE64"]))' "$T/cert.p12"
  "$PY" -c 'import base64,os,sys;open(sys.argv[1],"wb").write(base64.b64decode(os.environ["MOBILEPROVISION_BASE64"]))' "$T/profile.mobileprovision"
  chmod 600 "$T/cert.p12" "$T/profile.mobileprovision"

  security create-keychain -p "$KP" "$KEYCHAIN"
  security set-keychain-settings -lut 3600 "$KEYCHAIN"
  security unlock-keychain -p "$KP" "$KEYCHAIN"
  security import "$T/cert.p12" -k "$KEYCHAIN" -P "$P12_PASSWORD" -T /usr/bin/codesign -A
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KP" "$KEYCHAIN" >/dev/null
  local EXISTING
  EXISTING="$(security list-keychains -d user | tr -d '"' | tr '\n' ' ')"
  security list-keychains -d user -s "$KEYCHAIN" $EXISTING

  local CERT="${CERT_NAME:-}"
  if [ -z "$CERT" ]; then
    CERT="$(security find-identity -v -p codesigning "$KEYCHAIN" \
            | sed -n 's/.*"\(Apple Distribution:.*\)"/\1/p; s/.*"\(iPhone Distribution:.*\)"/\1/p' | head -1)"
  fi
  [ -n "$CERT" ] || fail "在 p12 中找不到分发证书，请显式设置 Secret: CERT_NAME"
  note "签名身份: $CERT"

  # 安装描述文件到 runner（Xcode/ASC 校验时会用到）
  mkdir -p "$HOME/Library/MobileDevice/Provisioning Profiles"
  security cms -D -i "$T/profile.mobileprovision" > "$T/profile.plist"
  local UUID
  UUID="$("$PY" -c 'import plistlib,sys;r=open(sys.argv[1],"rb").read();i=r.find(b"<?xml");print(plistlib.loads(r[i:] if i>=0 else r)["UUID"])' "$T/profile.plist")"
  cp "$T/profile.mobileprovision" "$HOME/Library/MobileDevice/Provisioning Profiles/$UUID.mobileprovision"

  # 记录原 IPA 的顶层条目，重打包后逐一比对（防止丢 SwiftSupport 等）
  "$PY" - "$IPA" "$T/ipa-tops.txt" <<'PY'
import zipfile, sys
z = zipfile.ZipFile(sys.argv[1])
tops = sorted({n.split("/")[0] for n in z.namelist()
               if n.split("/")[0] and not n.startswith("__MACOSX")})
open(sys.argv[2], "w").write("\n".join(tops))
PY
  rm -rf "$WORK/unpack"
  mkdir -p "$WORK/unpack"
  unzip -q "$IPA" -d "$WORK/unpack"
  local APP
  APP="$(find "$WORK/unpack/Payload" -maxdepth 1 -type d -name '*.app' | head -1)"
  [ -n "$APP" ] || fail "解包后找不到 Payload/*.app"

  # 提升最低部署系统：保留原 plist 格式（二进制/XML），随后整个 bundle 会重新 codesign，
  # CodeResources 中的 Info.plist 摘要也会随新签名一起重建。
  "$PY" - "$APP/Info.plist" "$MIN_OS_VERSION" "$ATS_STRICT" <<'PY'
import plistlib, sys
path, want, ats_strict = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(path, "rb").read()
fmt = plistlib.FMT_BINARY if raw.startswith(b"bplist00") else plistlib.FMT_XML
info = plistlib.loads(raw)
old = info.get("MinimumOSVersion", "<缺失>")
info["MinimumOSVersion"] = want
print("::notice::MinimumOSVersion: %s -> %s (plist fmt=%s)"
      % (old, want, "binary" if fmt == plistlib.FMT_BINARY else "xml"))
if ats_strict.lower() == "true":
    old_ats = info.get("NSAppTransportSecurity", "<缺失>")
    # 严格 ATS：不列任何例外域名，避免把微信平台域名写进白名单而被审核视为自证
    info["NSAppTransportSecurity"] = {"NSAllowsArbitraryLoads": False}
    print("::notice::NSAppTransportSecurity: %s -> NSAllowsArbitraryLoads=false (2.5.19)"
          % (old_ats if isinstance(old_ats, str) else str(old_ats)))
with open(path, "wb") as f:
    plistlib.dump(info, f, fmt=fmt)
PY

  # 主 App 的 entitlements 以「新描述文件」为基准重建：
  #   原签名里的 application-identifier / team-identifier / get-task-allow 带旧 Team，
  #   沿用会出现 ITMS-90163 或装不上；SDK 依赖但 profile 未声明的能力键才从旧签名补齐。
  local ENT="$T/entitlements.plist"
  local OLD_ENT="$T/ent.old.plist"
  : > "$OLD_ENT"
  codesign -d --entitlements :- --xml "$APP" > "$OLD_ENT" 2>/dev/null || true
  "$PY" - "$T/profile.plist" "$OLD_ENT" "$ENT" <<'PY'
import plistlib, sys

def load(path):
    try:
        return plistlib.load(open(path, "rb"))
    except Exception:
        return {}

prof = load(sys.argv[1]).get("Entitlements", {})
old = load(sys.argv[2])
merged = dict(prof)
forced = ("application-identifier", "com.apple.developer.team-identifier",
          "get-task-allow", "beta-reports-active")
for k in forced:
    if k in prof:
        merged[k] = prof[k]
# 只补齐白名单内的 SDK 能力键，避免把 aps-environment=development 之类脏值带进去
keep = ("keychain-access-groups", "com.apple.developer.associated-domains",
        "com.apple.developer.networking.wifi-info",
        "com.apple.external-accessory.wireless-configuration")
for k in keep:
    if k in old and k not in merged:
        merged[k] = old[k]
plistlib.dump(merged, open(sys.argv[3], "wb"))
aid = str(merged.get("application-identifier", ""))
team = str(merged.get("com.apple.developer.team-identifier", ""))
if not aid or not team or aid.split(".")[0] != team:
    print("::error::描述文件的 application-identifier 与 Team ID 不一致: %s / %s" % (aid, team))
    sys.exit(1)
print("::notice::entitlements 已按新 profile 重建: %s / get-task-allow=%s / 键数=%d"
      % (aid, merged.get("get-task-allow"), len(merged)))
PY

  # 换成 Secrets 中的描述文件（须在主 App 签名之前）
  cp "$T/profile.mobileprovision" "$APP/embedded.mobileprovision"

  # 嵌套代码按路径深度倒序签名；dylib/framework 一律不带 entitlements
  # （微信云端打包给 Swift dylib 误加 entitlements 会导致 ITMS-91166，重签可顺带消除）
  "$PY" - "$WORK/unpack/Payload" "$T/sign-order.bin" "$APP" <<'PY'
import os, sys
root, out, main_app = sys.argv[1], sys.argv[2], os.path.abspath(sys.argv[3])
items = []
for dp, dn, fn in os.walk(root):
    for n in dn:
        if n.endswith((".framework", ".appex", ".app", ".xctest")):
            items.append(os.path.join(dp, n))
    for n in fn:
        if n.endswith((".dylib", ".so")):
            items.append(os.path.join(dp, n))
items = [p for p in items if os.path.abspath(p) != main_app]
items.sort(key=lambda p: (p.count(os.sep), len(p)), reverse=True)
open(out, "wb").write(b"\0".join(p.encode() for p in items) + b"\0")
PY

  local item ent_file
  while IFS= read -r -d '' item; do
    [ -n "$item" ] || continue
    ent_file=""
    case "$item" in
      *.appex|*.app|*.xctest)
        if codesign -d --entitlements :- --xml "$item" > "$T/ent.tmp.plist" 2>/dev/null \
           && [ -s "$T/ent.tmp.plist" ]; then
          ent_file="$T/ent.tmp.plist"
        fi
        ;;
    esac
    if [ -n "$ent_file" ]; then
      codesign --force --sign "$CERT" --keychain "$KEYCHAIN" --entitlements "$ent_file" "$item"
    else
      codesign --force --sign "$CERT" --keychain "$KEYCHAIN" "$item"
    fi
  done < "$T/sign-order.bin"

  # 主 App 最后签
  codesign --force --sign "$CERT" --keychain "$KEYCHAIN" --entitlements "$ENT" "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -10
  note "重签完成: $CERT / profile $UUID"

  # -y 保留 framework 内符号链接；必须打包全部顶层条目
  # （实测原 IPA 含 SwiftSupport/iphoneos/libswift_Concurrency.dylib，只打 Payload 会丢 Swift 运行时）
  find "$WORK/unpack" -name '.DS_Store' -delete 2>/dev/null || true
  local NEW="$T/app-resigned.ipa"
  rm -f "$NEW"
  ( cd "$WORK/unpack" && zip -qry "$NEW" * )
  "$PY" - "$NEW" "$T/ipa-tops.txt" <<'PY'
import os, sys, zipfile, plistlib
z = zipfile.ZipFile(sys.argv[1])
tops = sorted({n.split("/")[0] for n in z.namelist()
               if n.split("/")[0] and not n.startswith("__MACOSX")})
want = open(sys.argv[2]).read().splitlines()
missing = [t for t in want if t not in tops]
print("::notice::重打包顶层条目: %s" % ", ".join(tops))
if z.testzip():
    print("::error::重打包后的 IPA ZIP 损坏")
    sys.exit(1)
if missing:
    print("::error::重打包丢失顶层条目: %s" % ", ".join(missing))
    sys.exit(1)
infos = [n for n in z.namelist()
         if n.startswith("Payload/") and n.endswith(".app/Info.plist") and n.count("/") == 2]
if len(infos) != 1:
    print("::error::重打包后找不到唯一的主 App Info.plist")
    sys.exit(1)
want_os = os.environ.get("MIN_OS_VERSION", "15.0")
got_os = str(plistlib.loads(z.read(infos[0])).get("MinimumOSVersion", "<缺失>"))
print("::notice::重打包后 MinimumOSVersion = %s (要求 %s)" % (got_os, want_os))
if got_os != want_os:
    print("::error::MinimumOSVersion 未生效: %s != %s" % (got_os, want_os))
    sys.exit(1)
PY
  mv "$NEW" "$IPA"
}

# ---------- 主流程 ----------
[ -f "$IPA" ] || fail "IPA 不存在: $IPA"
[ "$(uname -s)" = "Darwin" ] && IS_MAC=1 || IS_MAC=0

inspect

APP_DIR=""
if [ "$IS_MAC" = "1" ]; then
  rm -rf "$WORK/unpack"
  mkdir -p "$WORK/unpack"
  unzip -q "$IPA" -d "$WORK/unpack"
  APP_DIR="$(find "$WORK/unpack/Payload" -maxdepth 1 -type d -name '*.app' | head -1)"
  [ -n "$APP_DIR" ] || fail "解包后找不到 Payload/*.app"
fi

case "$MODE" in
  verify)
    note "模式 verify：只验签，不改动 IPA（云构建产物已带分发签名）"
    if [ "$IS_MAC" = "1" ]; then verify_macos "$APP_DIR"; else
      note "Linux runner：跳过 codesign / mobileprovision 深度校验（结构与版本已校验）"
    fi
    ;;
  resign)
    [ "$IS_MAC" = "1" ] || fail "resign 只能在 macOS runner 上执行"
    resign_macos
    inspect
    verify_macos "$APP_DIR"
    note "重签后 IPA 大小: $(wc -c < "$IPA") bytes"
    ;;
  *)
    fail "未知模式: $MODE（只能是 verify 或 resign）"
    ;;
esac

note "完成: $IPA ($MODE)"
