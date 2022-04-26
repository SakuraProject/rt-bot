# Free RT Util - webhooks

import discord
from discord.ext import commands
from typing import Optional


async def get_webhook(
    channel: discord.TextChannel, name: str = "RT-Tool"
) -> Optional[discord.Webhook]:
    "ウェブフックを取得します。"
    return discord.utils.get(await channel.webhooks(), name=name)


async def webhook_send(
    channel, *args, webhook_name: str = "RT-Tool", **kwargs
):
    """`channel.send`感覚でウェブフック送信をするための関数です。  
    `channel.webhook_send`のように使えます。  

    Parameters
    ----------
    *args : tuple
        discord.pyのWebhook.sendに入れる引数です。
    webhook_name : str, defualt "RT-Tool"
        使用するウェブフックの名前です。  
        存在しない場合は作成されます。
    **kwargs : dict
        discord.pyのWebhook.sendに入れるキーワード引数です。"""
    if isinstance(channel, commands.Context):
        channel = channel.channel
    wb = (
        wb if (
            wb := discord.utils.get(await channel.webhooks(), name=webhook_name)
        ) else await channel.create_webhook(name=webhook_name))
    try:
        return await wb.send(*args, **kwargs)
    except discord.InvalidArgument as e:
        if webhook_name == "RT-Tool":
            return await webhook_send(channel, *args, webhook_name="R2-Tool", **kwargs)
        else:
            raise e
