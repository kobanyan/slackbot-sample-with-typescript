import * as http from 'http';
import * as express from 'express';
import * as contentType from 'content-type';
import * as getRawBody from 'raw-body';
import * as crypto from 'crypto';

const app = express();

/**
 * raw body を取得するための処理。
 * これで req['text'] に raw body の Buffer が入るようになる。
 */
app.use((req, res, next) => {
  getRawBody(req, {
    length: req.headers['content-length'],
    limit: '1mb',
    encoding: contentType.parse(req).parameters.charset,
  }, function (err, string) {
    if (err) {
      return next(err);
    }
    req['text'] = string;
    next();
  });
});

app.post('/', (req, res, next) => {
  // ヘッダからタイムスタンプを取得。キーはすべて小文字。
  const timestamp = req.headers['x-slack-request-timestamp'] as string;
  // タイムスタンプが5分以上ずれていたらエラーにする。
  if (Math.abs(parseInt(timestamp, 10) - Math.floor(new Date().getTime() / 1000)) > 60 * 5) {
    res.sendStatus(403);
    return;
  }
  // ヘッダから署名を取得する。キーはすべて小文字。
  const actualSignature = req.headers['x-slack-signature'] as string;
  // 署名の元となる文字列を作成。
  const sigBaseString = `v0:${timestamp}:${req['text']}`;
  // Signing Secret をキーにして、 sha256 アルゴリズムを使用した hmac を作成。
  const hmac = crypto.createHmac('sha256', process.env.SLACK_SIGNING_SECRET);
  // 計算する。
  const digest = hmac.update(sigBaseString).digest('hex');
  // 頭に v0= を付けて完成。
  const expectedSignature = `v0=${digest}`;
  // 送られてきた署名と計算した署名を比較し、一致していなければエラーにする。
  if (actualSignature !== expectedSignature) {
    res.sendStatus(403);
    return;
  }
  res.send('pong!');
});

http.createServer(app).listen(8081, () => {
  console.log('server listening on port 8081');
});
