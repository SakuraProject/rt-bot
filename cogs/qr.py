import os
import cv2
import discord
import pyqrcode
from discord.ext import commands


class qr(commands.Cog): 

    def __init__(self, bot): 
        self.bot = bot

    @commands.group(
        extras={
            "headding": {"ja": "qr関連のコマンドです", "en": "qr command"},
            "parent": "Entertainment"
        }
    )
    async def qr(self, ctx): 
        """!lang ja
        --------
        qrコード関連のコマンドです。sub_commands: make, read

        !lang en
        --------
        qr category command。sub_commands: make, read"""
        if ctx.invoked_subcommand is None:
            return await ctx.send("使用方法が違います。")

    @qr.command(
        extras={
            "headding": {"ja": "文字からqrコードを作成します", "en": "making qr code on string"},
            "parent": "Entertainment"
        }
    )
    async def make(self, ctx, text): 
        a = pyqrcode.create(content=text, error='H') 
        a.png(file=str(ctx.author.id) + '.png', scale=6)
        await ctx.send(file=discord.File(str(ctx.author.id) + '.png'))
        os.remove(str(ctx.author.id) + '.png')

    @qr.command(
        extras={
            "headding": {"ja": "qrコードを読み取ります", "en": "read qr code"},
            "parent": "Entertainment"
        }
    )
    async def read(self, ctx, url=None): 
        if url is None: 
            url = ctx.message.attachments[0].url
        async with self.bot.session.get(url) as resp:
            with open(str(ctx.author.id) + 'r.png', 'wb') as fp:
                while True: 
                    r = await resp.content.read(10)  # 4
                    if not r: 
                        break
                    fp.write(r)
        image = cv2.imread(str(ctx.author.id) + 'r.png')
        qrDetector = cv2.QRCodeDetector()
        data, bbox, rectifiedImage = qrDetector.detectAndDecode(image)
        await ctx.send(data)
        os.remove(str(ctx.author.id) + 'r.png')


def setup(bot): 
    bot.add_cog(qr(bot))
