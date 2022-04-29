# Free RT - TopGG

from topgg import DBLClient


def setup(bot):
    if not hasattr(bot, "topgg") and not bot.test:
        bot.topgg = DBLClient(
            bot, bot.secret["topgg"],
            autopost=True, post_shard_count=True
        )
