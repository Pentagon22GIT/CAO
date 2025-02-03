import random


class ToyHomomorphicEncryption:
    def __init__(self, scale=100000, noise_bound=10, byte_length=32):
        """
        scale: 平文を拡大する定数。値が大きいほど丸め誤差が小さくなります。
        noise_bound: 暗号化時に付加する雑音の上限（-noise_bound～noise_bound）
        byte_length: 暗号文を固定長バイト列にするためのバイト長（ここでは256ビット＝32バイト）
        """
        self.scale = scale
        self.noise_bound = noise_bound
        self.byte_length = (
            byte_length  # 固定長のバイト数。出力はこのバイト数を16進数文字列に変換する
        )

    def _encode(self, value):
        """
        整数 value を固定長（byte_length バイト）の2の補数表現のバイト列に変換し、
        16進数文字列にエンコードします。
        これにより、暗号文は常に同じ桁数の文字列となります。
        """
        return value.to_bytes(self.byte_length, byteorder="big", signed=True).hex()

    def _decode(self, cipher_str):
        """
        16進数文字列 cipher_str をバイト列に戻し、2の補数表現として整数に変換します。
        """
        return int.from_bytes(bytes.fromhex(cipher_str), byteorder="big", signed=True)

    def encrypt(self, m):
        """
        平文 m（浮動小数点数）を暗号化します。
        m を scale 倍して整数化し、そこに -noise_bound～noise_bound のランダムな雑音を加え、
        固定長文字列（16進数）にエンコードします。
        """
        noise = random.randint(-self.noise_bound, self.noise_bound)
        value = int(m * self.scale) + noise
        return self._encode(value)

    def decrypt(self, cipher_str):
        """
        暗号文（固定長16進数文字列）を整数にデコードし、scale で割って平文を近似復元します。
        """
        value = self._decode(cipher_str)
        # 小さい雑音が加わっているため、round() により平文を概ね正しく復元します。
        return round(value / self.scale, 5)

    def add(self, cipher1, cipher2):
        """
        同型加算：2つの暗号文文字列をデコードして整数の加算を行い、
        結果を再度固定長文字列にエンコードします。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        result = int1 + int2
        return self._encode(result)

    def subtract(self, cipher1, cipher2):
        """
        同型減算：2つの暗号文文字列をデコードして整数の減算を行い、
        結果を固定長文字列にエンコードします。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        result = int1 - int2
        return self._encode(result)

    def multiply(self, cipher1, cipher2):
        """
        同型乗算：
          2つの暗号文文字列をデコードして整数の乗算を行います。
          なお、各暗号文は平文に scale をかけた整数表現となっているため、
          乗算後は scale^2 倍になっているので、scale で割る（丸める）ことで元のスケールに戻します。
          結果は固定長文字列にエンコードして返します。
        """
        int1 = self._decode(cipher1)
        int2 = self._decode(cipher2)
        product = int1 * int2
        # 乗算後のスケール調整：scale^2 → scale に戻すために scale で割る
        result = int(round(product / self.scale))
        return self._encode(result)

    def inverse(self, cipher, iterations=5):
        """
        同型逆数計算（ニュートン‐ラフソン法による近似）:
          暗号文 cipher に対応する平文 m の逆数 1/m を暗号文上で近似計算します。
          初期値は encrypt(1.0) としており、平文 m が概ね [1,2] の範囲にある場合に収束する前提です。

          更新式:
              y_{n+1} = y_n * (2 - c * y_n)
        """
        y = self.encrypt(1.0)  # 初期値: 1.0 の暗号文
        two_enc = self.encrypt(2.0)
        for i in range(iterations):
            cy = self.multiply(cipher, y)  # c * y_n
            diff = self.subtract(two_enc, cy)  # 2 - c * y_n
            y = self.multiply(y, diff)  # 更新: y_{n+1} = y_n * (2 - c * y_n)
        return y

    def divide(self, cipher1, cipher2, iterations=5):
        """
        同型除算:
          暗号文 cipher1 を cipher2 で割る操作は、cipher2 の逆数を求めた上で乗算することで実現します。
          ※逆数計算の近似は平文が [1,2] の範囲にあることを前提としています。
        """
        inv_cipher2 = self.inverse(cipher2, iterations)
        return self.multiply(cipher1, inv_cipher2)


if __name__ == "__main__":
    fhe = ToyHomomorphicEncryption()

    # --- USER1, USER2 がそれぞれ平文を暗号化してサーバー（USER3）に送信 ---
    m = 7.0
    n = 3.0

    cipher_m = fhe.encrypt(m)
    cipher_n = fhe.encrypt(n)

    print("=== 平文の暗号化（固定長文字列で出力） ===")
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
    # （例：複数の暗号文の加算・平均などが可能です）
    # ※ここでは、単純な演算例として除算の例も示します。
    # 除算の近似計算では、逆数の収束条件のため平文は概ね [1,2] の範囲にあることが前提です。
    a = 1.4
    b = 1.2
    cipher_a = fhe.encrypt(a)
    cipher_b = fhe.encrypt(b)
    cipher_div = fhe.divide(cipher_a, cipher_b, iterations=7)

    print("\n=== 同型除算（平文が [1,2] 前提の近似計算） ===")
    print("USER1: 平文 a =", a, "→ 暗号文 =", cipher_a)
    print("USER2: 平文 b =", b, "→ 暗号文 =", cipher_b)
    print("暗号文 a / b =", cipher_div, "→ 復号結果（近似） =", fhe.decrypt(cipher_div))
