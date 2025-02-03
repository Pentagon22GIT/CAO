import random


class ToyHomomorphicEncryptionEnhanced:
    def __init__(
        self, scale=100000, noise_bound=10, byte_length=32, A_bits=120, B_bits=120
    ):
        """
        scale: 平文を拡大する定数（大きいほど丸め誤差が小さくなる）。
        noise_bound: 暗号化時に付加する雑音の上限（-noise_bound～noise_bound）。
        byte_length: 暗号文を固定長バイト列にするためのバイト数（例：32バイト＝256ビット）。
        A_bits: 秘密乗数 A のビット長（難読化のための第一段階）。
        B_bits: 追加の秘密乗数 B のビット長（暗号文が固定長全体に分布するようにする）。

        なお、ここでは最終的な暗号文を整数環 \( \mathbb{Z}_M \) （M = 2^(8*byte_length)）内の値として扱い、
        固定長の16進数文字列に変換します。
        """
        self.scale = scale
        self.noise_bound = noise_bound
        self.byte_length = byte_length
        # モジュラス M（例：256ビット）
        self.M = 2 ** (8 * self.byte_length)
        # 秘密乗数 A：平文の拡大値に対して乗じる（奇数にしておく）
        self.A = random.getrandbits(A_bits) | 1
        # 追加の秘密乗数 B：これにより暗号文が全ビット域に広がるようにする（奇数にして逆元が存在）
        self.B = random.getrandbits(B_bits) | 1
        # M内での B の逆元（B_inv * B ≡ 1 mod M）
        self.B_inv = pow(self.B, -1, self.M)

    def _encode(self, value):
        """
        整数 value を符号なしとして固定長（byte_length バイト）のバイト列に変換し、
        16進数文字列にエンコードします。
        """
        # value は 0 ≤ value < M を前提
        return value.to_bytes(self.byte_length, byteorder="big", signed=False).hex()

    def _decode(self, cipher_str):
        """
        固定長16進数文字列 cipher_str をバイト列に戻し、整数に変換します。
        """
        return int.from_bytes(bytes.fromhex(cipher_str), byteorder="big", signed=False)

    def encrypt(self, m):
        """
        暗号化処理：
          1. 平文 m（浮動小数点数）を scale 倍して整数化し、雑音を加えた値 base_val を得る。
          2. base_val に秘密乗数 A を掛け、さらに追加乗数 B を掛ける。
          3. 結果を M（2^(8*byte_length)）で割った余りとして固定長文字列にエンコードする。

        暗号化された値は、
           E(m) = ( base_val * A * B ) mod M
        となります。
        """
        noise = random.randint(-self.noise_bound, self.noise_bound)
        base_val = int(m * self.scale) + noise
        obf = (base_val * self.A * self.B) % self.M
        return self._encode(obf)

    def decrypt(self, cipher_str):
        """
        復号処理：
          1. 固定長文字列を整数にデコードし、B の効果を除去するために B_inv を掛ける。
          2. 得られた値を A で除して（四捨五入しながら）元の base_val を近似的に復元し、
          3. scale で割って平文 m（浮動小数点数）を得る。
        """
        obf = self._decode(cipher_str)
        # B の効果を除去
        val_with_A = (obf * self.B_inv) % self.M
        # A で割って base_val を得る（noise の影響は僅かなので四捨五入で調整）
        base_val = round(val_with_A / self.A)
        return round(base_val / self.scale, 5)

    def add(self, cipher1, cipher2):
        """
        同型加算：
          E(m1) + E(m2) = (base1*A*B + base2*A*B) mod M = ((base1+base2)*A*B) mod M,
          復号すると (base1+base2)/scale となるため、平文の加算に対応します。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        res = (int1 + int2) % self.M
        return self._encode(res)

    def subtract(self, cipher1, cipher2):
        """
        同型減算：
          E(m1) - E(m2) = ((base1 - base2)*A*B) mod M
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        res = (int1 - int2) % self.M
        return self._encode(res)

    def scalar_multiply(self, cipher, constant):
        """
        スカラー乗算：
          暗号文に定数を乗じることで、統計計算（合計、平均など）に利用可能です。
        """
        int_val = self._decode(cipher)
        res = int(round(int_val * constant)) % self.M
        return self._encode(res)

    def multiply(self, cipher1, cipher2):
        """
        同型乗算：
          各暗号文は E(m) = base * A * B として表されるので、
          cipher1 * cipher2 = (base1 * A * B) * (base2 * A * B) = base1*base2*A^2*B^2 (mod M)

          ここで、元の乗算結果に対応する暗号文は
             E(m1*m2) = (base1*base2 * A * B) mod M
          となるべきなので、余分な A*B の因子を除去するため、
          乗算後に (A*B*scale) で除算（丸め）して、再度 A*B を掛け直します。
          （scale による調整は、平文の乗算結果のスケール調整のため）
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        product = (int1 * int2) % self.M  # = base1*base2*A^2*B^2 mod M
        # 補正：余分な A*B を除去してスケール調整
        corrected = int(round(product / (self.A * self.B * self.scale)))
        # 再度、難読化（ただしここでは追加雑音は入れず、演算の結果としての暗号文を生成）
        new_cipher = (corrected * self.A * self.B) % self.M
        return self._encode(new_cipher)

    def inverse(self, cipher, iterations=5):
        """
        同型逆数の近似（ニュートン‐ラフソン法）:
          反復法を用いて、暗号文上で 1/m を近似計算します。
          更新式: y_{n+1} = y_n * (2 - c * y_n)
          ※初期値は encrypt(1.0) としており、平文 m が概ね [1,2] の範囲にある場合の収束を前提とします。
        """
        y = self.encrypt(1.0)
        two_enc = self.encrypt(2.0)
        for i in range(iterations):
            cy = self.multiply(cipher, y)
            diff = self.subtract(two_enc, cy)
            y = self.multiply(y, diff)
        return y

    def divide(self, cipher1, cipher2, iterations=5):
        """
        同型除算：
          cipher1 / cipher2 は、cipher2 の逆数を求めた上で乗算することで実現します。
        """
        inv_cipher2 = self.inverse(cipher2, iterations)
        return self.multiply(cipher1, inv_cipher2)

    # 以下は、統計処理の例として、複数の暗号文データから合計・平均・分散を計算する関数の例です。
    def encrypted_sum(self, cipher_list):
        """暗号文リストの同型加算"""
        total = self.encrypt(0.0)
        for c in cipher_list:
            total = self.add(total, c)
        return total

    def encrypted_average(self, cipher_list):
        """暗号文リストの平均（スカラー乗算を利用）"""
        total = self.encrypted_sum(cipher_list)
        n = len(cipher_list)
        return self.scalar_multiply(total, 1 / n)

    def encrypted_variance(self, cipher_list):
        """暗号文リストの分散 (E[X^2] - (E[X])^2) を計算"""
        n = len(cipher_list)
        sum_sq = self.encrypt(0.0)
        for c in cipher_list:
            c_sq = self.multiply(c, c)
            sum_sq = self.add(sum_sq, c_sq)
        avg_sq = self.scalar_multiply(sum_sq, 1 / n)
        avg = self.encrypted_average(cipher_list)
        avg_of_sq = self.multiply(avg, avg)
        return self.subtract(avg_sq, avg_of_sq)


if __name__ == "__main__":
    # インスタンス生成（平文は例えば 1.0～2.0 の範囲と想定）
    fhe = ToyHomomorphicEncryptionEnhanced()

    # USER1, USER2 などから送信された平文データ（例として10件のランダムな値）
    num_data = 10
    plain_data = [round(random.uniform(1.0, 2.0), 5) for _ in range(num_data)]
    print("【平文データ】")
    print(plain_data)

    # 各平文を暗号化（送信データとして固定長16進数文字列になる）
    encrypted_data = [fhe.encrypt(x) for x in plain_data]

    # USER3 が受け取った暗号文のまま、同型演算による統計処理を実施
    enc_sum = fhe.encrypted_sum(encrypted_data)
    enc_avg = fhe.encrypted_average(encrypted_data)
    enc_var = fhe.encrypted_variance(encrypted_data)

    # 復号して統計結果を確認（復号できるのは秘密情報を持つ認可ユーザーのみ）
    sum_val = fhe.decrypt(enc_sum)
    avg_val = fhe.decrypt(enc_avg)
    var_val = fhe.decrypt(enc_var)

    print("\n【USER3 による暗号文上での統計処理結果】")
    print("暗号化された合計:", enc_sum)
    print("暗号化された平均:", enc_avg, "→ 復号結果 =", avg_val)
    print("暗号化された分散:", enc_var, "→ 復号結果 =", var_val)
