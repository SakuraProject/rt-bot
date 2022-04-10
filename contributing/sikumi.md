# RT全体の仕組み
RT全体の仕組みは以下の図を見るとわかりやすいと思います。  
  
(図は作成中...)  
  
RT本体はrt-botで動かすことができます。しかし、backend(サーバーサイド)とは通信をしなければならないため単体で動かすことは不可能です。  
また、frontendはクライアントサイドなので特にサーバーは必要ありません。

## free RTが現在どこまで構築できているか
freeRTは現在ほぼすべての外部接続(Backend、Frontendなど)を削除した状態で動いています。  
さらに限定的なCogのみを読み込んで動いているため、現在は仮の状態です。  
テストを重ね安定し次第、段階的に機能を開放する予定です。