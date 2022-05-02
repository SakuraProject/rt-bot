# Free RT Util - MySQL Manager

from typing import Any, Dict, Tuple

from asyncio import get_event_loop, iscoroutinefunction
from aiomysql import create_pool, connect
from functools import wraps
import warnings
import ujson


warnings.filterwarnings('ignore', module=r"aiomysql")


class Cursor:
    """データベースの操作を簡単に行うためのクラスです。  
    `Cursor.get_data`などの便利なものが使えます。  
    `MySQLManager.get_cursor`から取得することができます。
    このクラスは「`MySQLManager.get_cursor`から取得」と書きましたが、もちろん下にあるParametersを見て自分で定義することもできます。
    例：`cursor = Cursor(MySQLManager)`

    Notes
    -----
    データベースの操作をする場合は`Cursor.prepare_cursor`を実行しないとなりません。  
    そしてデータベースの操作を終えた後は`Cursor.close`を実行しないといけません。  
    ですがこれは`async with`文で代用することができます。  
    もしデータベースを操作した場合は`MySQLManager.commit`を通常は実行する必要がありますが、`Cursor`のデータベースを変更するものは全て自動で`MySQLManager.commit`を実行します。  
    これは引数の`commit`をFalseにすることで自動で実行しなくなります。  
    もし連続でデータベースの操作をする場合はこの引数`commit`をFalseにして操作終了後に自分で`MySQLManager.commit`を実行する方が効率的でしょう。

    Example
    -------
    db = MySQLManager(...)
    async with db.get_cursor() as cursor:
        row = await cursor.get_data("test", {"column1": "tasuren"})
    print(row)

    Parameters
    ----------
    db : MySQLManager
        データベースマネージャーです。

    Attributes
    ----------
    loop : asyncio.AbstractEventLoop
        イベントループです。
    connection
        データベースとの接続です。
    cursor
        データベースの操作などに使うカーソルです。  
        `Cursor.prepare_cursor`を実行するまではこれは有効になりません。"""
    def __init__(self, db):
        self.cursor = None
        self.loop, self.connection = db.loop, db.connection

    async def prepare_cursor(self):
        """Cursorを使えるようにします。  
        データベースの操作をするにはこれを実行する必要があります。  
        そして操作後は`Cursor.close`を実行する必要があります。

        Notes
        -----
        これを使用する代わりに`async with`文を使用することが可能です。"""
        self.cursor = await self.connection.cursor()
        self.cursor._defer_warnings = True

    async def close(self):
        """Curosorを閉じます。"""
        if self.cursor is not None:
            await self.cursor.close()
            self.cursor = None

    def __del__(self):
        if not self.loop.is_closed():
            self.loop.create_task(self.close())

    async def __aenter__(self):
        await self.prepare_cursor()
        return self

    async def __aexit__(self, ex_type, ex_value, trace):
        await self.close()

    async def create_table(self, table: str, columns: Dict[str, str],
                           if_not_exists: bool = True, commit: bool = True) -> None:
        """テーブルを作成します。

        Parameters
        ----------
        table : str
            テーブルの名前です。
        columns : Dict[str, str]
            作成する列の名前と型名の辞書です。  
            例：`{"name": "TEXT", "data": "TEXT"}`
        if_not_exists : bool, default True
            テーブルが存在しない場合作るようにするかどうかです。
        commit : bool, default True
            テーブルの作成後に自動で`MySQLManager.commit`をするかどうかです。"""
        if_not_exists = "IF NOT EXISTS " if if_not_exists else ""
        values = ", ".join(f"{key} {columns[key]}" for key in columns)
        await self.cursor.execute(f"CREATE TABLE {if_not_exists}{table} ({values});")
        if commit:
            await self.connection.commit()
        del if_not_exists, values

    async def drop_table(self, table: str, commit: bool = True) -> None:
        """テーブルを削除します。

        Parameters
        ----------
        table : str
            削除するテーブルの名前です。
        if_exists : bool, default True
            もしテーブルが存在するならテーブルを削除するかどうかです。
        commit : bool, default True
            テーブル削除後に自動で`MySQLManager.commit`を実行するかどうかです。"""
        await self.cursor.execute(f"DROP TABLE {table};")
        if commit:
            await self.connection.commit()

    def _get_column_args(
            self, values: Dict[str, Any], format_text: str = "{} = %s AND ",
            json_dump: bool = False
    ) -> Tuple[str, list]:
        conditions, args = "", []
        for key in values:
            conditions += format_text.format(key)
            args.append(
                ujson.dumps(values[key])
                if json_dump and isinstance(values[key], dict)
                else values[key]
            )
        return conditions, args

    async def insert_data(
        self, table: str, values: Dict[str, Any],
        commit: bool = True, json: bool = False
    ) -> None:
        """特定のテーブルにデータを追加します。  

        Paremeters
        ----------
        table : str
            対象のテーブルです。
        values : Dict[str, Any]
            列名とそれに対応する追加する値です。  
            辞書は自動でjsonになります。
        commit : bool, default True
            追加後に自動で`MySQLManager.commit`を実行するかどうかです。  
            もし複数のデータを一度で追加する場合はこれを`False`にして終わった後に自分でcommitをしましょう。

        Examples
        --------
        async with db.get_cursor() as cursor:
            values = {"name": "Takkun", "data": {"detail": "愉快"}}
            await cursor.post_data("tasuren_friends", values)"""
        conditions, args = self._get_column_args(
            values, "{}, ", json_dump=True
        )
        query = ("%s, " * len(args))[:-2]
        await self.cursor.execute(
            f"INSERT INTO {table} ({conditions[:-2]}) VALUES ({query})",
            args
        )
        if commit:
            await self.connection.commit()

    async def update_data(
        self, table: str, values: Dict[str, Any],
        targets: Dict[str, Any], commit: bool = True,
        json: bool = False
    ) -> None:
        """特定のテーブルの特定のデータを更新します。

        Parameters
        ----------
        table : str
            対象のテーブルです。
        values : Dict[str, Any]
            更新する内容です。
        targets : Dict[str, Any]
            更新するデータの条件です。
        commit : bool, default True
            更新後に自動で`MySQLManager.commit`を実行するかどうかです。"""
        values, values_args = self._get_column_args(
            values, "{} = %s, ", True
        )
        conditions, conditions_args = self._get_column_args(
            targets, json_dump=True
        )
        await self.cursor.execute(
            f"UPDATE {table} SET {values[:-2]} WHERE {conditions[:-4]}",
            values_args + conditions_args
        )
        if commit:
            await self.connection.commit()

    async def exists(self, table: str, targets: Dict[str, Any], json: bool = False) -> bool:
        """特定のテーブルに特定のデータが存在しているかどうかを確認します。

        Parameters
        ----------
        table : str
            対象のテーブルです。
        targets : Dict[str, Any]
            存在確認をするデータの条件です。

        Returns
        -------
        exists : bool
            存在しているならTrue、存在しないならFalseです。"""
        return bool(await self.get_data(table, targets, json=json))

    async def delete(
        self, table: str, targets: Dict[str, Any], commit: bool = True,
        json: bool = False
    ) -> None:
        """特定のテーブルにある特定のデータを削除します。

        Parameters
        ----------
        table : str
            対象のテーブルです。
        targets : Dict[str, Any]
            削除するデータの条件です。
        commit : bool, default True
            削除後に自動で`MySQLManager.commit`を実行するかどうかです。"""
        conditions, args = self._get_column_args(targets, json_dump=True)
        await self.cursor.execute(
            f"DELETE FROM {table} WHERE {conditions[:-4]}",
            args
        )
        if commit:
            await self.connection.commit()

    async def get_datas(
        self, table: str, targets: Dict[str, Any],
        _fetchall: bool = True, custom: str = "",
        json: bool = False
    ) -> list:
        """特定のテーブルにある特定の条件のデータを取得します。  
        見つからない場合は空である`[]`が返されます。  
        ジェネレーターです。

        Parameters
        ----------
        table : str
            対象のテーブルです。
        targets : Dict[str, Any]
            取得するデータの条件です。

        Yields
        ------
        list
            取得したデータのリストです。  
            yieldで返され`[なにか, なにか, なにか, なにか]`のようになっています。  
            もしjsonがあった場合は辞書になります。  
            見つからない場合は空である`[]`となります。

        Notes
        -----
        もし条件関係なく全てを取得したい場合は引数の`targets`を空である`{}`にしましょう。"""
        if targets:
            conditions, args = self._get_column_args(
                targets, json_dump=True
            )
            conditions = " WHERE " + conditions[:-4]
        else:
            conditions, args = "", ()
        await self.cursor.execute(
            f"SELECT * FROM {table}{conditions}{' ' + custom if custom else custom}",
            args
        )
        if _fetchall:
            list_rows = await self.cursor.fetchall()
        else:
            list_rows = [await self.cursor.fetchone()]
        if list_rows:
            for rows in list_rows:
                if rows is None:
                    yield []
                else:
                    rows = [
                        ((ujson.loads(row) if (row and row[0] == "{" and row[-1] == "}")else row)
                         if isinstance(row, str) else row)
                        for row in rows if row is not None
                    ]
                    yield rows
                    if not _fetchall:
                        break
        else:
            yield []

    async def get_data(self, table: str, targets: Dict[str, Any], json: bool = False) -> list:
        """一つだけデータを取得します。  
        引数は`Cursor.get_datas`と同じです。

        Examples
        --------
        async with db.get_cursor() as cursor:
            targets = {"name": "Takkun"}
            row = await cursor.get_data("tasuren_friends", targets)
            if row:
                print(row[1])
                # -> "Takkun"
                print(row[-1])
                # -> {"detail": "愉快"} (辞書データ)"""
        return [row async for row in self.get_datas(table, targets, _fetchall=False, json=json)][0]


class MySQLManager:
    """MySQLを簡単に使うためのモジュールです。  
    aiomysqlを使用しています。  
    プールを使用することもできます。  
    複数のコグから使うなどの場合はプールモードで定義しましょう。

    Notes
    -----
    データベースの操作はこのクラスにあるものだけではできません。  
    データベースの操作を行うなら`Cursor`を使いましょう。  
    `Cursor`は`MySQLManager.get_cursor`で定義済みのものを取得することができます。  
    このクラスをプールモードで定義したの場合は、そのクラスは`get_cursor`や`commit`などが使用できません。  
    これを使用する場合はプールからコネクションを取得する必要があります。  
    これは`MySQLManager.get_database`から取得可能です。  
    これで取得したものはプールモードをオフにして定義したこのクラスと同等です。

    Parameters
    ----------
    pool : bool, default False
        プールを使用します。
    **kwargs : dict
        `aiomysql.connect`または`aiomysql.create_pool`に渡すキーワード引数です。

    Attributes
    ----------
    connection
        aiomysqlのMySQLとのコネクションです。  
        プールの場合は使えません。
    pool
        aiomysqlのプールです。  
        プールじゃない場合は使えません。
    loop : asyncio.AbstractEventLoop
        使用しているイベントループです。

    Examples
    --------
    # 普通
    db = util.MySQLManager(
        loop=bot.loop, user="root", password="I wanna be the guy", db="mysql")
    async with db.get_cursor() as cursor:
        ...
    # プールとして使う場合
    pool = util.MySQLManager(
        loop=bot.loop, user="root", password="I wanna be the guy", db="mysql")
    db = pool.get_database()
    async with db.get_cursor() as cursor:
        ..."""

    def __init__(self, pool: bool = False, _pool_c=False, **kwargs):
        self.connection, self.pool = None, None
        self._real_pool = None
        self.loop = kwargs.get("loop", get_event_loop())
        self.loop.create_task(self._setup(pool, _pool_c, kwargs))

    async def _setup(self, pool, _pool_c, kwargs) -> None:
        # データベースの準備をする。
        if pool and not _pool_c:
            self.pool = await create_pool(**kwargs)
        elif not _pool_c:
            self.connection = await connect(**kwargs)

    async def get_database(self):
        """このクラスの定義済みのものをプールを使って取得します。  
        これはこのクラスの定義時`pool=True`と言う引数を作っている場合のみ使用できます。  

        Warnings
        --------
        これはデータベースへの接続が終わってから実行してください。"""
        new = self.__class__(_pool_c=True, loop=self.loop)
        new.connection = await self.pool.acquire()
        new._real_pool = self.pool
        new.use = True
        return new

    async def commit(self):
        """変更をセーブします。"""
        await self.connection.commit()

    def get_cursor(self) -> Cursor:
        """データベースの操作を楽にするためのクラスのインスタンスを取得します。"""
        cursor = Cursor(self)
        return cursor

    def close(self):
        """データベースとの接続を終了します。"""
        self.__del__()

    def __del__(self):
        if self.connection is not None:
            self._real_pool.release(self.connection)
            self.connection = None
        if self.pool is not None:
            self.pool.close()


class DatabaseManager:
    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        for c in cls.__mro__:
            if (cls.__name__.startswith("Data")
                    and not c.__name__.startswith(
                        ("DatabaseL", "DatabaseM"))):
                for name in dir(c):
                    if not name.startswith("_"):
                        coro = getattr(cls, name)
                        if iscoroutinefunction(coro):
                            setattr(cls, name, cls.prepare_cursor(coro))

    async def _close(self, conn, cursor):
        await cursor.close()
        conn.close()
        del cursor

    @staticmethod
    def prepare_cursor(coro):
        @wraps(coro)
        async def new_coro(self, *args, **kwargs):
            conn = await self.db.get_database()
            cursor = conn.get_cursor()
            await cursor.prepare_cursor()
            try:
                data = await coro(self, cursor, *args, **kwargs)
            except Exception as e:
                await self._close(conn, cursor)
                raise e
            else:
                await self._close(conn, cursor)
                return data
        return new_coro
