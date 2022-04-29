# Free RT - Voice Role

from typing import Union

from discord.ext import commands, tasks
import discord
from util.mysql_manager import DatabaseManager
from util import RT


class DataManager(DatabaseManager):

    DB = "VoiceRole"

    def __init__(self, db, maxsize: int = 30):
        self.db = db
        self._maxsize = maxsize

    async def init_table(self, cursor) -> None:
        await cursor.create_table(
            self.DB, {
                "GuildID": "BIGINT", "ChannelID": "BIGINT",
                "RoleID": "BIGINT"
            }
        )

    async def write(
        self, cursor, guild_id: int,
        channel_id: int, role_id: int
    ) -> str:
        target = {
            "GuildID": guild_id, "ChannelID": channel_id,
            "RoleID": role_id
        }
        if await cursor.exists(self.DB, target):
            await cursor.delete(self.DB, target)
            return "削除 / remove"
        elif await self._get_length(cursor, guild_id) >= self._maxsize:
            raise OverflowError("これ以上設定できません。")
        else:
            await cursor.insert_data(self.DB, target)
            return "追加 / add"

    async def read(
        self, cursor, guild_id: int, channel_id: int
    ) -> tuple:
        target = {"GuildID": guild_id, "ChannelID": channel_id}
        if await cursor.exists(self.DB, target):
            return await cursor.get_data(self.DB, target)
        else:
            return ()

    async def _get_length(self, cursor, guild_id: int) -> int:
        target = {"GuildID": guild_id}
        if await cursor.exists(self.DB, target):
            return len([row async for row in cursor.get_datas(self.DB, target)])
        else:
            return 0


class VoiceRole(commands.Cog, DataManager):
    def __init__(self, bot: RT):
        self.bot = bot
        self.bot.loop.create_task(self.init_database())
        self.queue = {}

    async def init_database(self) -> None:
        super(commands.Cog, self).__init__(self.bot.mysql)
        await self.init_table()
        self.worker.start()

    @commands.command(
        aliases=["vr", "ボイスロール", "音声役職", "ぼいすろーる"], extras={
            "headding": {
                "ja": "音声チャンネルに接続した際に特定の役職を付与または剥奪する機能。",
                "en": "The ability to grant or revoke a specific title when connected to an audio channel."
            }, "parent": "ServerUseful"
        }
    )
    async def voicerole(
        self, ctx, channel: Union[discord.VoiceChannel, discord.StageChannel],
        *, role: discord.Role
    ):
        """!lang ja
        --------
        ボイスロール機能です。  
        この機能を使えば特定のボイスチャンネルに誰かが入った際に特定の役職を付与することができます。  
        この機能とDiscordの役職を持っているメンバーを別で表示する機能を使うことで、現在ボイスチャンネルにいる人などという表示を役職を使ってできます。

        Parameters
        ----------
        channel : 音声チャンネルの名前
            対象の音声チャンネルの名前です。
        role : 役職の名前またはメンション
            その音声チャンネルに接続または切断した際になんの役職を付与または剥奪するかです。

        Examples
        --------
        `rf!voicerole 雑談部屋 雑談中`

        Notes
        -----
        設定を削除する際は設定時と同じコマンドでできます。  
        この機能で設定できるボイスロールの数は三十個までです。  
        また削除されている役職の付与または剥奪をRTがしようとした場合はその設定は削除されます。  
        また全てのチャンネルに設定したい場合は`rf!vrall 役職の名前またはメンション`で設定をすることができます。  
        それとAPI制限防止のため役職の付与または剥奪が数秒遅れることがあります。  
        そして素早く接続切断を繰り返した場合は行われないことがあります。

        See Also
        --------
        linker : 特定の役職を付与または剥奪した際に特定の他の役職も付与または剥奪をする機能。

        Warnings
        --------
        役職は音声チャンネルに接続してから最大五秒ほどは待たないと付与または剥奪されません。  
        これは接続と切断を繰り返してRTの処理を妨害するというのを対策するためのものです。  
        ご了承ください。  
        それと付与または剥奪する役職はRTの役職より下にある必要があります。  
        そうじゃないと権限の関係で付与または剥奪を実行できない可能性があります。

        Aliases
        -------
        vr, ボイスロール, ぼいすろーる, 音声役職

        !lang en
        --------
        Voice Role function.  
        With this feature, you can assign a specific role to someone when they enter a specific voice channel.  
        By using this feature and Discord's ability to show members with different roles, you can show who is currently in a voice channel, etc. using the role.

        Parameters
        ----------
        channel : Name of the voice channel
            The name of the target voice channel.
        role : the name of the role or mention
            The role to be assigned or revoked when connecting to or disconnecting from the voice channel.

        Examples
        --------
        `rf!voicerole chat room chatting

        Notes
        -----
        If you want to delete a setting, you can do so with the same command you used to set it.  
        The number of voice roles that can be set with this function is limited to 30.  
        If RT tries to grant or revoke a deleted role, the setting will be deleted.

        See Also
        --------
        linker : If you grant or revoke a specific role, it will also grant or revoke other positions.

        Warnings
        --------
        You must wait up to five seconds after connecting to the voice channel for a position to be granted or revoked.  
        This is to prevent people from repeatedly connecting and disconnecting, which can interfere with the RT process.  
        Please be aware of this.  
        Also, the role to be granted or revoked must be lower than the RT role.  
        If not, it may not be possible to grant or revoke due to permissions.

        Aliases
        -------
        vr"""
        await ctx.trigger_typing()
        try:
            mode = await self.write(ctx.guild.id, channel.id, role.id)
        except OverflowError:
            await ctx.reply("VoiceRoleは15個まで設定が可能です。")
        else:
            await ctx.reply(f"Ok {mode}")

    @commands.command()
    async def vrall(self, ctx, *, role: discord.Role):
        await ctx.trigger_typing()
        for channel in ctx.guild.voice_channels:
            try:
                await self.write(ctx.guild.id, channel.id, role.id)
            except OverflowError:
                await ctx.reply(
                    "VoiceRoleは30個まで設定が可能です。\nなので一部は設定されませんでした。"
                )
                break
        else:
            await ctx.reply("Ok")

    @tasks.loop(seconds=5)
    async def worker(self):
        for key in list(self.queue.keys()):
            for member, roles in list(self.queue[key].items()):
                # 被りを削除する。
                new_roles = []
                for mode, role in roles:
                    if (mode, role) not in new_roles:
                        new_roles.append((mode, role))
                del roles
                # 役職を付与または削除する。
                for mode, role in new_roles:
                    try:
                        has_role = member.get_role(role.id)
                        if mode == "join" and not has_role:
                            await member.add_roles(role)
                        elif mode == "leave" and has_role:
                            await member.remove_roles(role)
                    except Exception as e:
                        if self.bot.test:
                            print("Error on VoiceRole:", e)
                    finally:
                        self.queue[key][member].remove((mode, role))
                else:
                    del self.queue[key][member]
                    if not self.queue[key]:
                        del self.queue[key]

    async def on_member(self, mode, member, after):
        if member.guild and after.channel:
            row = await self.read(member.guild.id, after.channel.id)
            if row:
                role = member.guild.get_role(row[2])
                if role:
                    # API制限対策でキューに追加してWorkerが処理する形にする。
                    if row[1] not in self.queue:
                        self.queue[row[1]] = {}
                    if member not in self.queue[row[1]]:
                        self.queue[row[1]][member] = []
                    self.queue[row[1]][member].append((mode, role))
                else:
                    # もし役職が見つからないなら削除する。
                    await self.write(*row)

    def cog_unload(self):
        self.worker.cancel()

    @commands.Cog.listener()
    async def on_voice_join(self, member, before, after):
        await self.on_member("join", member, after)

    @commands.Cog.listener()
    async def on_voice_leave(self, member, before, after):
        await self.on_member("leave", member, before)


def setup(bot):
    bot.add_cog(VoiceRole(bot))
