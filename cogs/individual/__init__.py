from os import listdir


async def setup(bot):
    for name in listdir("cogs/individual"):
        if not name.startswith(("_", ".")):
            try:
                await bot.load_extension(
                    f"cogs.individual.{name[:-3] if name.endswith('.py') else name}")
            except Exception as e:
                print(e)
            else:
                bot.print("[Extension]", "Loaded", name)  # ロードログの出力
