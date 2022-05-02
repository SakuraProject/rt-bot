# RT test_all

def test_util():
    "util関連のテストをします。"
    import util
    assert "mysql" in dir(util)


def test_cog():
    "Cog関連のテストをします。"
    import cogs
    assert all("setup" in dir(getattr(cogs, m))
               for m in dir(cogs)
               if not m.startswith(("_", ".")))
