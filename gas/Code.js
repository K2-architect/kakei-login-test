/**
 * 家計アプリ ログイン試作（API）
 *
 * GitHub Pages の画面から POST で呼ぶ。Googleログインの IDトークンを確かめ、
 * アプリ独自のセッショントークン（30日）を返す。
 * ウェブアプリとして「次のユーザーとして実行＝自分」「アクセスできるユーザー＝全員」でデプロイする。
 *
 * スクリプト プロパティ
 * - OAUTH_CLIENT_ID：Google Cloud で作った OAuth クライアントID
 * - SESSION_SECRET ：セッションの署名に使う鍵（appApiNewSecret をエディタから実行して作る）
 * - ALLOWED_EMAILS ：使ってよいメールアドレス（カンマ区切り）
 *
 * この認証部分（appApi で始まる関数）は、本番の app_api.gs / kw_api.gs にそのまま移す。
 */

const APP_API_VER = 1;
const APP_API_SESSION_DAYS = 30;

/** 画面から呼べる操作（who はログイン中の人 { email }） */
const APP_API_ACTIONS = {
  'ping': function (payload, who) {
    return { pong: true, email: who.email, time: new Date().toISOString() };
  }
};

function doPost(e) {
  let req = null;
  try { req = JSON.parse((e && e.postData && e.postData.contents) || ''); } catch (err) { req = null; }
  if (!req || typeof req !== 'object' || typeof req.action !== 'string') {
    return appApiOut_({ ok: false, error: { code: 'BAD_REQUEST', message: 'リクエストの形式が正しくありません。' } });
  }
  try {
    if (req.action === 'auth.login') return appApiOut_({ ok: true, data: appApiLogin_(req.payload || {}) });
    const who = appApiCheckSession_(req.session);
    if (!Object.prototype.hasOwnProperty.call(APP_API_ACTIONS, req.action)) {
      throw appApiError_('BAD_REQUEST', 'この操作はできません。画面を開き直してください。');
    }
    return appApiOut_({ ok: true, data: APP_API_ACTIONS[req.action](req.payload || {}, who) });
  } catch (err) {
    if (err && err.apiCode) return appApiOut_({ ok: false, error: { code: err.apiCode, message: err.message } });
    console.error(err);
    return appApiOut_({ ok: false, error: { code: 'INTERNAL', message: 'エラーが発生しました。しばらくしてからもう一度お試しください。' } });
  }
}

// 「全員」がアクセスできるデプロイなので、ここでは画面もデータも出さない
function doGet() {
  return ContentService.createTextOutput('このURLはアプリのデータ用です。');
}

/** 最初に1回だけエディタから実行する。使ってよい人は、実行した本人だけにする */
function appApiSetup() {
  const p = PropertiesService.getScriptProperties();
  p.setProperty('OAUTH_CLIENT_ID', '840191511985-n1q868keqd0bt3rj1877ntkd58hq47lp.apps.googleusercontent.com');
  p.setProperty('ALLOWED_EMAILS', Session.getEffectiveUser().getEmail());
  if (!p.getProperty('SESSION_SECRET')) appApiNewSecret();
  console.log('設定しました。');
}

/** セッションの鍵を作り直す（エディタから実行）。実行すると、ログイン中の全員がログインし直しになる */
function appApiNewSecret() {
  PropertiesService.getScriptProperties().setProperty('SESSION_SECRET', Utilities.getUuid() + Utilities.getUuid());
  console.log('セッションの鍵を作り直しました。');
}

/* ───────── 認証 ───────── */

/** Googleログインの IDトークンを確かめ、セッショントークンを返す */
function appApiLogin_(payload) {
  const idToken = String(payload.idToken || '');
  if (!idToken) throw appApiError_('AUTH_REQUIRED', 'ログインしてください。');
  const res = UrlFetchApp.fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(idToken), { muteHttpExceptions: true });
  let info = null;
  if (res.getResponseCode() === 200) {
    try { info = JSON.parse(res.getContentText()); } catch (err) { info = null; }
  }
  const clientId = appApiProp_('OAUTH_CLIENT_ID');
  const now = Math.floor(Date.now() / 1000);
  if (!info || !clientId || info.aud !== clientId ||
      (info.iss !== 'accounts.google.com' && info.iss !== 'https://accounts.google.com') ||
      !(Number(info.exp) > now) || String(info.email_verified) !== 'true' || !info.email) {
    throw appApiError_('AUTH_EXPIRED', 'ログインを確認できませんでした。もう一度ログインしてください。');
  }
  const email = String(info.email).toLowerCase();
  if (!appApiAllowed_(email)) throw appApiError_('FORBIDDEN', 'このアカウントでは使えません。');
  const exp = now + APP_API_SESSION_DAYS * 86400;
  return { session: appApiSign_({ email: email, exp: exp, ver: APP_API_VER }), email: email, exp: exp };
}

/** セッショントークンを確かめ、ログイン中の人を返す。だめなら例外 */
function appApiCheckSession_(session) {
  const t = String(session || '');
  if (!t) throw appApiError_('AUTH_REQUIRED', 'ログインしてください。');
  const expired = appApiError_('AUTH_EXPIRED', 'ログインの期限が切れました。もう一度ログインしてください。');
  const parts = t.split('.');
  if (parts.length !== 2 || !appApiSame_(parts[1], appApiMac_(parts[0]))) throw expired;
  let s = null;
  try { s = JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(parts[0])).getDataAsString()); } catch (err) { s = null; }
  if (!s || s.ver !== APP_API_VER || !(Number(s.exp) > Date.now() / 1000) || !s.email) throw expired;
  if (!appApiAllowed_(s.email)) throw appApiError_('FORBIDDEN', 'このアカウントでは使えません。');
  return { email: s.email };
}

function appApiSign_(obj) {
  const body = Utilities.base64EncodeWebSafe(JSON.stringify(obj), Utilities.Charset.UTF_8).replace(/=+$/, '');
  return body + '.' + appApiMac_(body);
}

function appApiMac_(body) {
  const secret = appApiProp_('SESSION_SECRET');
  if (!secret) throw new Error('SESSION_SECRET が設定されていません。');
  return Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(body, secret)).replace(/=+$/, '');
}

/** 文字列の比較（かかる時間から中身を推測されないよう、最後まで比べる） */
function appApiSame_(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function appApiAllowed_(email) {
  const list = appApiProp_('ALLOWED_EMAILS').split(',').map(function (x) { return x.trim().toLowerCase(); });
  return !!email && list.indexOf(String(email).toLowerCase()) >= 0;
}

function appApiProp_(name) {
  return String(PropertiesService.getScriptProperties().getProperty(name) || '').trim();
}

function appApiError_(code, message) {
  const err = new Error(message);
  err.apiCode = code;
  return err;
}

function appApiOut_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
