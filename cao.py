import random
import math

# ===== グローバルパラメータ =====

# 暗号化する平文の最大バイト数（例：16バイト以内）
MAX_PLAINTEXT_LEN = 16

# メルセンヌ素数 p = 2^521 - 1（521ビットの素数：十分大きい）
p = 2**521 - 1

# CT_BODY_LEN: p を表現するのに必要な固定バイト数（521ビット ≒ 66バイト）
CT_BODY_LEN = 66

# 秘密鍵 K（例として 0～255 の整数）
K = random.randint(0, 255)

# 秘密の乗数 A （pは素数なので、1～p-1 の任意の値は逆元を持つ）
A = random.randint(1, p - 1)
# A の逆元（p は素数なので pow(A, -1, p) で求められる）
A_inv = pow(A, -1, p)

# デバッグ用（実際の運用では秘密情報は隠すべきです）
print(f"[DEBUG] p = {p}")
print(f"[DEBUG] 秘密鍵 K = {K}")
print(f"[DEBUG] 乗数 A = {A}")
print(f"[DEBUG] Aの逆元 A_inv = {A_inv}")


# ===== 補助関数 =====
def F(L: int) -> int:
    """F(L) = (256^L - 1) // 255　（L >= 0）"""
    if L == 0:
        return 0
    return (256**L - 1) // 255


def int_to_fixed_bytes(n: int, length: int) -> bytes:
    """整数 n を、指定バイト数 length の big-endian バイト列（ゼロ埋め）に変換"""
    return n.to_bytes(length, byteorder="big")


def bytes_to_int(b: bytes) -> int:
    """バイト列を整数に変換（big-endian）"""
    return int.from_bytes(b, byteorder="big")


# ===== 改良版 暗号化／復号関数 =====
def encrypt_string_improved(plaintext: str) -> str:
    """
    平文を暗号化する。
    ・平文は UTF-8 でバイト列に変換し、その長さ L を取得（MAX_PLAINTEXT_LEN バイト以内）
    ・平文整数 m を得る。
    ・内部計算： X = m + K * F(L)
    ・さらに、C_internal = A * X mod p とし、これを固定長（CT_BODY_LEN バイト）の16進数文字列にする。
    ・ヘッダー部として平文長 L を1バイト（16進数2桁）で付与。
    ・最終的な暗号文は「ヘッダー＋本文部」で一定長の文字列となる。
    """
    pt_bytes = plaintext.encode("utf-8")
    L = len(pt_bytes)
    if L > MAX_PLAINTEXT_LEN:
        raise ValueError(
            f"平文は最大 {MAX_PLAINTEXT_LEN} バイトまでです。（入力長 {L} バイト）"
        )
    m = int.from_bytes(pt_bytes, "big")
    # 内部計算（整数演算）：X = m + K * F(L)
    X = m + K * F(L)
    # ブラインディング：C_internal = A * X mod p
    C_internal = (A * X) % p
    # 固定長表現：C_internal を CT_BODY_LEN バイトに変換
    body = int_to_fixed_bytes(C_internal, CT_BODY_LEN).hex()
    # ヘッダー部：平文長 L を1バイト（16進数2桁）で表現
    header = L.to_bytes(1, "big").hex()
    ct_str = header + body
    return ct_str


def decrypt_string_improved(ct_str: str) -> str:
    """
    暗号文（16進数文字列）を復号する。
    ・先頭1バイト（2文字）から平文のバイト長 L を得る。
    ・本文部全体から整数 C_internal を取得し、X = C_internal * A_inv mod p とする。
    ・平文整数 m = X - K * F(L) を得、これを L バイトのバイト列に変換して UTF-8 で復号する。
    """
    # 固定長チェックは削除または緩和
    if len(ct_str) < 2:
        raise ValueError("暗号文が短すぎます。")
    header = ct_str[:2]
    body_hex = ct_str[2:]
    L = int(header, 16)
    # 本文部のバイト数は、16進数文字列なので半分
    body_byte_len = len(body_hex) // 2
    C_internal = int(body_hex, 16)
    # 復号：X = (C_internal * A_inv) mod p
    X = (C_internal * A_inv) % p
    m = X - K * F(L)
    # 平文 m を L バイトに変換（ゼロ埋め）
    m_bytes = int_to_fixed_bytes(m, L)
    try:
        plaintext = m_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext = "<復号エラー>"
    return plaintext


def homomorphic_concat_improved(ct_str1: str, ct_str2: str) -> str:
    """
    2 つの暗号文（固定長文字列）に対し、以下の同型的連結を行う。
    1. 各暗号文から、ヘッダー部（平文バイト長 L1, L2）と本文部（整数 C1, C2）を抽出。
    2. 演算： C_concat = C1 * 256^(L2) + C2, L_concat = L1 + L2 とする。
       ※実際、C1 = A*(m1+K*F(L1))、C2 = A*(m2+K*F(L2)) なので、
         C_concat = A*(m1*256^(L2)+m2+K*(F(L1)*256^(L2)+F(L2)))
         となり、F(L1)*256^(L2)+F(L2) = F(L1+L2) であるため、連結された暗号文は
         A*(m_concat+K*F(L_concat)) となる。
    3. 結果をヘッダー部（L_concat を1バイト）＋本文部（固定長 CT_BODY_LEN バイト）の16進数文字列として出力する。
    ※ p が十分大きければラップアラウンドは発生しません。
    """
    if len(ct_str1) != (1 * 2 + CT_BODY_LEN * 2) or len(ct_str2) != (
        1 * 2 + CT_BODY_LEN * 2
    ):
        raise ValueError("入力暗号文の長さが不正です。")
    L1 = int(ct_str1[:2], 16)
    L2 = int(ct_str2[:2], 16)
    C1 = int(ct_str1[2:], 16)
    C2 = int(ct_str2[2:], 16)
    # 同型的連結演算
    C_concat = C1 * (256**L2) + C2
    L_concat = L1 + L2
    # 結果の本文部を固定長 CT_BODY_LEN バイトに変換
    body_concat = int_to_fixed_bytes(C_concat, CT_BODY_LEN + L2).hex()
    header_concat = L_concat.to_bytes(1, "big").hex()
    return header_concat + body_concat


# ===== デモンストレーション =====
if __name__ == "__main__":
    # Aさんが "HELLO" を暗号化して送信
    plaintext_A = "HELLO"
    ct_A = encrypt_string_improved(plaintext_A)
    print("\n[Aさんの暗号化結果]")
    print("平文:", plaintext_A)
    print("暗号文:", ct_A)

    # Bさんが "HEY" を暗号化して送信
    plaintext_B = "HEY"
    ct_B = encrypt_string_improved(plaintext_B)
    print("\n[Bさんの暗号化結果]")
    print("平文:", plaintext_B)
    print("暗号文:", ct_B)

    # Cさん：受信した暗号文同士を同型的に連結（足し合わせ）する
    ct_concat = homomorphic_concat_improved(ct_A, ct_B)
    print("\n[Cさんによる暗号文連結結果]")
    print("連結後の暗号文:", ct_concat)
    # Cさんは内部の秘密（K, A）は知らないため、平文は判読できない

    # Aさん：連結された暗号文を復号して "HELLOHEY" を得る
    plaintext_concat = decrypt_string_improved(ct_concat)
    print("\n[Aさんによる復号結果]")
    print("復号平文:", plaintext_concat)  # 期待: "HELLOHEY"
