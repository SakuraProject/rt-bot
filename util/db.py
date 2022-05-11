"""
freeRT式新データベースマネージャーです。
このマネージャーはdiscord.pyのCogのように使うことができます。
※他のbotには応用しにくい仕組みとなっています。申し訳ありません。
コード例:
```python
from util import db

class Managerrr(db.DBManager):
    def __init__(self, bot):
        self.bot = bot

    async def manager_load(self, cursor):
        # マネージャーが読み込まれた時の特殊関数。
        await cursor.execute("CREATE TABLE user(ID BIGINT, description TEXT, fuga TEXT)")

    async def check_user_id(self, obj: Any):
        return util.isintable(obj) and self.bot.get_user(obj)

    @db.command()
    async def add_user(self, cursor, user: str):
        if not self.check_user_id(user):
            return False
        await cursor.execute("INSERT INTO USERS VALUES(%s, %s, %s)", (int(user), "", ""))

    @db.command(auto=False)
    async def get_user(self, conn, user_id: str):
        if not self.check_user:
            return False
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM USERS WHERE ID=%s", (user_id,))
            return await cursor.fetchone()

class Coooog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def cog_load(self):
        self.db = await self.bot.add_db_manager(Managerrr(bot))

    @commands.command()
    async def datacheck(self, ctx, id: int):
        result = self.db.get_user.run()
        await ctx.send(result if result else "見つかりませんでした。")
```
"""


async def add_db_manager(bot, manager):
    async with bot.mysql.pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await manager.manager_load()


class DBManager:
    def __init__:
        pass
