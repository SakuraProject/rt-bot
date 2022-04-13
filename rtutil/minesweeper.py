# Mine Sweeper Game Engin
# by tasuren

from random import randrange


class Ms:
    def __init__(self, mx, my, bomb, log=False):
        self.reset(mx, my, bomb)

        self.check = lambda x, y: (
            (x - 1, y + 1),
            (x, y + 1),
            (x + 1, y + 1),
            (x - 1, y),
            (x, y),
            (x + 1, y),
            (x - 1, y - 1),
            (x, y - 1),
            (x + 1, y - 1),
        )
        self.check_end = lambda n: self.mx * self.my - self.bomb == len(
            sum([[x for x in y if x not in self.objs] for y in n], [])
        )
        self.get_raw = lambda: self.now
        self.get_raw_answer = lambda: self.b

    def reset(self, mx, my, bomb, log=False):
        self.log = log
        self.objs = ["#", "-", "%"]
        self.now = [["-" for x in range(mx)] for y in range(mx)]
        self.b = [["-" for x in range(mx)] for y in range(mx)]
        self.bomb, self.mx, self.my = bomb, mx, my
        for i in range(bomb):
            while True:
                x = randrange(mx)
                y = randrange(my)
                if self.b[y][x] != self.objs[0]:
                    break
            self.b[y][x] = self.objs[0]

    def back_get(self, l, margin):
        r = (
            " "
            + margin * 2
            + margin.join(
                [
                    "0" * (len(str(self.mx)) - len(str(x))) + str(x + 1)
                    for x in range(self.mx)
                ]
            )
            + "\n"
        )
        for y in range(len(l)):
            r += margin + ("0" * (len(str(self.my)) - len(str(y)))) + str(y + 1)
            for x in l[y]:
                r += margin + x
            r += "\n"
        return r

    def get(self, margin=""):
        return self.back_get(self.now, margin)

    def get_answer(self, margin=""):
        return self.back_get(self.b, margin)

    def rep(self, x, y, z, mode=0):
        c, bombs = self.check(x, y), 0
        for i in range(2):
            for cx, cy in c:
                if cx == -1 or cy == -1:
                    continue
                if self.log:
                    print(f"  Set {cx} {cy}")
                try:
                    if self.b[cy][cx] == self.objs[0]:
                        bombs += 1
                    self.now[y][x] = str(
                        (self.objs[2] if self.now[y][x] != self.objs[2] else "-")
                        if z
                        else int(bombs / 2)
                    )
                    self.b[y][x] = str(
                        (self.objs[2] if self.b[y][x] != self.objs[2] else "-")
                        if z
                        else int(bombs / 2)
                    )
                except IndexError:
                    continue
            if bombs == 0 and bombs != self.objs[2]:
                for cx, cy in c:
                    if self.log:
                        print(f"  Set {cx} {cy}")
                    if (
                        cx == -1
                        or cy == -1
                        or self.my <= cy
                        or self.mx <= cx
                        or [cx, cy] in self.did
                    ):
                        continue
                    self.did.append([cx, cy])
                    self.rep(cx, cy, False, mode=1)

    def set(self, x, y, z=False):
        self.did = []
        x, y = int(x) - 1, int(y) - 1

        if len(self.b) <= y:
            return 200
        if len(self.b[0]) <= x:
            return 200

        sl = self.b[y][x]
        if sl == self.objs[1]:
            self.rep(x, y, z)
            if self.check_end(self.b) and not z:
                return 301
            else:
                return 200
        elif sl == self.objs[0] and not z:
            self.now[y][x] = self.objs[0]
            self.now
            return 410
        else:
            return 200


if __name__ == "__main__":
    x, y, z = input("x y bomb>").split()
    ms = Ms(int(x), int(y), int(z))
    kek = 200
    while True:
        print(ms.get(" "))
        z = input("x y or cmd>").split()
        if len(z) == 0:
            continue
        x = z[0]
        if x == "answer":
            print(ms.get_answer(" "))
            continue
        if x == "exit":
            break
        y = z[1]
        z = True if len(z) > 2 else False
        kek = ms.set(int(x), int(y), z)
        if kek == 410:
            print(ms.get_answer(" ") + "\nGAME OVER\nYou lost !")
            break
        if kek == 301:
            print(ms.get_answer(" ") + "\nGAME OVER\nYou won !")
            break
