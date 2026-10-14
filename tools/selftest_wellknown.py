# -*- coding: utf-8 -*-
"""自测：协议性公开豁免（`.well-known`）。

★ 这批用例的由来：jarvis-registry 排除测试文件后只剩 3 处inconsistent_auth，
  逐条读源码定性后发现其中 2 处是 **OIDC Discovery + JWKS** ——
  按 RFC 8414 / RFC 7517 **必须无鉴权公开**，报出来是纯噪声。

★★★ 关键设计取舍（别改回去）：
  只豁免 `.well-known` 前缀，**不豁免裸的 `/jwks`、`/keys`、`/.well-known` 之外**。
  理由：协议性公开是**标准强制的**（不公开 = 设计错误），
  而业务自定的公开端点是**项目自己的选择**（可能是疏忽，值得扫出来）。
  把两者混进同一个豁免表，就分不清"该不该报"了。
"""
import io
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ast_criteria import _is_exempt_path  # noqa: E402

CASES = [
    # (路径, 期望豁免, 说明)
    ("/.well-known/openid-configuration", True,
     "OIDC Discovery（RFC 8414）—— 客户端靠它发现 token_endpoint"),
    ("/.well-known/jwks.json", True,
     "JWKS（RFC 7517）—— 验证方靠它拉公钥，不公开才是设计错误"),
    ("/.well-known/oauth-authorization-server", True,
     "RFC 8414 的另一个元数据端点"),
    ("/.well-known/webfinger", True, "同一族协议性公开端点"),
    ("/.well-known/assetlinks.json", True, "Android 资产链接"),

    # ★ 反向：这些**不能**豁免
    ("/api/jwks", False,
     "★★ 裸 /jwks 常是业务自定端点，未必是协议要求，保留扫描"),
    ("/api/keys", False, "同上"),
    ("/api/v1/.well-known-ish", False,
     "★ 只认 `.well-known` 这一段，前缀里带别的字不算"),
    ("/api/well-known", False, "少一个点，不是 RFC 规定的前缀"),
    ("/api/v1/sessions/{sid}", False, "业务端点，必须扫"),
    ("/oauth2/token", True, "既有豁免覆盖（token 端点本来就公开）"),
    ("/api/authorize", True, "既有豁免覆盖"),
    ("/health", True, "既有豁免覆盖"),
    ("/api/v1/iam/users", False, "业务端点"),
]

bad = 0
for path, want, why in CASES:
    got = _is_exempt_path(path)
    ok = (got == want)
    bad += (not ok)
    print("  %s %-42s 期望=%-5s 实际=%-5s  %s"
          % ("OK  " if ok else "FAIL", path, want, got, why))

print()
print("失败 %d / %d" % (bad, len(CASES)))
sys.exit(1 if bad else 0)
