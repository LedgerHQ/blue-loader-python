from ecpy.curves import Curve, Point


class PedersenVSS:
    def __init__(self, curve: Curve):
        self.curve = curve
        self.P = Point(curve.generator.x, curve.generator.y, curve)
        self.domain_len = curve.generator.x.bit_length() // 8

    def pedersen_commit(self, Q: Point, a: int, b: int) -> Point:
        point1 = self.curve.mul_point(a, self.P)
        point2 = self.curve.mul_point(b, Q)

        return self.curve.add_point(point1, point2)

    def pedersen_share_commit(self, Q: Point, share: bytes) -> Point:
        a = int.from_bytes(share[: self.domain_len], "big")
        b = int.from_bytes(share[self.domain_len :], "big")
        return self.pedersen_commit(Q, a, b)

    def pedersen_verify_commit(self, Q: Point, share: bytes, index: int, commits: list):
        s_point = self.pedersen_share_commit(Q, share)

        r_point = commits[0]

        for i in range(1, len(commits)):
            r = self.curve.mul_point(index**i, commits[i])
            r_point = self.curve.add_point(r_point, r)

        return s_point == r_point, s_point
