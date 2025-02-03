import random


class ToyHomomorphicEncryptionObfuscated:
    def __init__(self, scale=100000, noise_bound=10, byte_length=32, obf_bits=200):
        """
        scale: 平文を拡大する定数。値が大きいほど丸め誤差が小さくなる。
        noise_bound: 暗号化時に付加する雑音の上限（-noise_bound～noise_bound）
        byte_length: 暗号文を固定長バイト列にするためのバイト数（例：32バイト＝256ビット）
        obf_bits: 秘密の難読化乗数（A）のビット長。暗号化された値に乗じて、見た目のランダム性を向上させる。
        """
        self.scale = scale
        self.noise_bound = noise_bound
        self.byte_length = byte_length
        # 秘密の難読化乗数 A を、obf_bits ビットの奇数としてランダムに選ぶ
        self.A = random.getrandbits(obf_bits) | 1

    def _encode(self, value):
        """
        整数 value を固定長（byte_length バイト）の2の補数表現に変換し、16進数文字列にします。
        これにより、常に同一長の文字列（例：64桁の16進数文字列）が得られます。
        """
        # value が負の場合も扱えるよう、signed=True
        return value.to_bytes(self.byte_length, byteorder="big", signed=True).hex()

    def _decode(self, cipher_str):
        """
        16進数文字列 cipher_str をバイト列に戻し、2の補数表現に基づいて整数に変換します。
        """
        return int.from_bytes(bytes.fromhex(cipher_str), byteorder="big", signed=True)

    def encrypt(self, m):
        """
        平文 m（浮動小数点数）を暗号化します。
          1. m を scale 倍して整数化（雑音を加えます）。
          2. 得られた値に秘密乗数 A を乗じ、難読化します。
          3. 結果の整数を固定長の16進数文字列にエンコードします。
        """
        noise = random.randint(-self.noise_bound, self.noise_bound)
        base_val = int(m * self.scale) + noise
        obfuscated = base_val * self.A
        return self._encode(obfuscated)

    def decrypt(self, cipher_str):
        """
        暗号文（固定長16進数文字列）を復号します。
          1. 16進数文字列を整数に変換。
          2. 秘密乗数 A で割って（実際は四捨五入して）元の整数値（base_val）を近似復元。
          3. scale で割ることで元の平文（浮動小数点数）に戻します。
        """
        obfuscated = self._decode(cipher_str)
        # A で割って元のスケール化前の整数に戻す（誤差は四捨五入で調整）
        base_val = round(obfuscated / self.A)
        return round(base_val / self.scale, 5)

    def add(self, cipher1, cipher2):
        """
        同型加算：
          各暗号文は A * (int(m*scale)+noise) となっているので、加算しても
          A が共通因子として残り、平文に対応する加算結果となる。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        result = int1 + int2
        return self._encode(result)

    def subtract(self, cipher1, cipher2):
        """
        同型減算：加算と同様、各暗号文は A 倍されているので、そのまま減算しても
          A が共通因子として残ります。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        result = int1 - int2
        return self._encode(result)

    def multiply(self, cipher1, cipher2):
        """
        同型乗算：
          各暗号文は A*(base_val) となっているため、乗算すると A^2 がかかる。
          そこで、乗算後に (A * scale) で除算（四捨五入）することで、
          A * round((base1 * base2) / scale)（すなわち E(m1*m2)）に戻します。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        product = int1 * int2  # これは A^2 * (base1*base2)
        # 乗算後のスケール調整：product/(A*scale) = A*(base1*base2)/scale
        result = int(round(product / (self.A * self.scale)))
        return self._encode(result)

    def inverse(self, cipher, iterations=5):
        """
        同型逆数計算（ニュートン‐ラフソン法による近似）:
          暗号文 cipher に対応する平文 m の逆数 1/m を、暗号文上で近似計算します。
          反復式は y_{n+1} = y_n * (2 - c * y_n) で、初期値は encrypt(1.0) とします。
          ※本近似法は、平文 m が概ね [1,2] の範囲にあるときに収束する前提です。
        """
        y = self.encrypt(1.0)  # 初期値: 1.0 の暗号文
        two_enc = self.encrypt(2.0)
        for i in range(iterations):
            cy = self.multiply(cipher, y)  # c * y_n
            diff = self.subtract(two_enc, cy)  # 2 - c*y_n
            y = self.multiply(y, diff)  # y_{n+1} = y_n * (2 - c*y_n)
        return y

    def divide(self, cipher1, cipher2, iterations=5):
        """
        同型除算:
          cipher1 / cipher2 は、cipher2 の逆数（inverse）を求めた上で乗算することで実現します。
          ※逆数計算の近似は平文が [1,2] の範囲にあることを前提としています。
        """
        inv_cipher2 = self.inverse(cipher2, iterations)
        return self.multiply(cipher1, inv_cipher2)


if __name__ == "__main__":
    fhe = ToyHomomorphicEncryptionObfuscated()

    # --- USER1, USER2 がそれぞれ平文を暗号化してサーバー（USER3）に送信 ---
    m = 7.0
    n = 3.0

    cipher_m = fhe.encrypt(m)
    cipher_n = fhe.encrypt(n)

    print("=== 平文の暗号化（固定長16進数文字列・難読化付き） ===")
    print("USER1: 平文 m =", m, "→ 暗号文 =", cipher_m)
    print("USER2: 平文 n =", n, "→ 暗号文 =", cipher_n)

    # --- USER3 が受け取った暗号文に対して、同型演算を実施 ---
    cipher_add = fhe.add(cipher_m, cipher_n)
    cipher_sub = fhe.subtract(cipher_m, cipher_n)
    cipher_mul = fhe.multiply(cipher_m, cipher_n)

    print("\n=== USER3 による同型演算 ===")
    print("暗号文 m + n =", cipher_add, "→ 復号結果 =", fhe.decrypt(cipher_add))
    print("暗号文 m - n =", cipher_sub, "→ 復号結果 =", fhe.decrypt(cipher_sub))
    print("暗号文 m * n =", cipher_mul, "→ 復号結果 =", fhe.decrypt(cipher_mul))

    # --- 統計処理などのため、USER3 は暗号状態で複数の演算結果を保持・集計可能 ---
    # ※ここでは、同型除算の例も示します（逆数計算の近似条件として平文は [1,2] 前提）。
    a = 1.4
    b = 1.2
    cipher_a = fhe.encrypt(a)
    cipher_b = fhe.encrypt(b)
    cipher_div = fhe.divide(cipher_a, cipher_b, iterations=7)

    print("\n=== 同型除算（平文が [1,2] 前提の近似計算） ===")
    print("USER1: 平文 a =", a, "→ 暗号文 =", cipher_a)
    print("USER2: 平文 b =", b, "→ 暗号文 =", cipher_b)
    print("暗号文 a / b =", cipher_div, "→ 復号結果（近似） =", fhe.decrypt(cipher_div))
