<!--[![Discord Bots](https://top.gg/api/widget/status/716496407212589087.svg)](https://top.gg/bot/716496407212589087) [![Discord Bots](https://top.gg/api/widget/servers/716496407212589087.svg)](https://top.gg/bot/716496407212589087) ![Discord](https://img.shields.io/discord/718641964672876614?label=support&logo=discord)-->
<!-- To do: この部分をFreeRTのbotや公式サーバーのものにする。-->
(日本語版のreadmeは[こちら](https://github.com/Free-RT/rt-bot/blob/main/readme.ja.md))
# Free RT Bot
This is an Discord's bot, Free RT.  
There is 'RT bot' in discord and we can use it for paying to tasuren, so please use RT if you have enough money.  
Free RT is a feature-rich bot with features that most bots have.  
It also has features that other bots don't have.  
Connect to Free RT, Discord's Bot account, to start Free RT's service.  
It also communicates with `rt-backend` via WebSocket for web authentication and so on.(But now do not and we are making. It will be coming soon.)  
If you don't know about RT, have a look at [here](https://rt-bot.com/).  
If you don't know about Free RT, have a look at [here](https://free-rt.com/).  

## LICENSE
`BSD 4-Clause License` (The `LICENSE` file has more details.)

## CONTRIBUTION
See [contributing](https://github.com/Free-RT/rt-bot/blob/main/contributing/).

## Installation.
## Dependencies.
Required.

* Python 3.10
* MySQL or MariaDB.
* Everything in `requirements.txt`.
* Run `rt-backend` if you want to use functions that require a backend such as authentication.
### Startup procedure: 1.
1. install required items with `pip install -r requirements.txt` 2.
2. write necessary TOKEN etc. to `auth.json` referring to `auth.template.json`. 3.
Put the `rt-module` repository in `util` and name the folder `rt_module`. 4.
4. run the program in the `rt-backend` repository.
   (This is optional and you need to do it if you want to run something that requires a backend such as authentication. 5.)
Run the tests with `python3 main.py test`.
   (In this case, TOKEN will be the one in the `test` key of `auth.json`.)

(In this case, TOKEN is the one in the key of `test` in `auth.json`.) * Read `readme.md` in `cogs/tts` if you want to run the readout.
### Run production.
The startup command is `sudo -E python3 main.py production` and you need `auth.json` TOKEN for `production`.
