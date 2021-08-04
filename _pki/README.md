# PKI技術を使った認証システム

https://lecture.ecc.u-tokyo.ac.jp/~hideo-t/introductions/ssh/ssh.html

https://qiita.com/angel_p_57/items/2e3f3f8661de32a0d432

https://qiita.com/okajima/items/036d7e751234f88fbe9a

https://mugmugblog.com/%e3%80%90python%e3%80%91diffie-hellman%e9%8d%b5%e4%ba%a4%e6%8f%9b%e3%81%ae%e4%bb%95%e7%b5%84%e3%81%bf%e3%82%92%e7%90%86%e8%a7%a3%e3%81%99%e3%82%8b/2/
### 公開鍵を使った身分証明の流れ

1. クライアントからサーバーに通信したいですというリクエスト
2. クライアントとサーバーでDHを使って共通鍵を共有する
3. 共有した共通鍵を使って認証を開始
4. 

### 1. ディレクトリサーバーの公開鍵の配置

事前にエンティティにはディレクトリサーバーの公開鍵を配置しておく
エンティティはその公開鍵を利用して
