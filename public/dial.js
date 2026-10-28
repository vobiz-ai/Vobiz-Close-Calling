/* The tel: handler page, and the target of Close Integration Links.
 *
 *  - The browser opens /dial?to=tel%3A%2B91... when the agent clicks a phone
 *    number in Close with "Call using tel: links" chosen.
 *  - An Integration Link can open /dial?contact=cont_... or /dial?lead=lead_...
 *    and the softphone offers that record's numbers.
 *
 * This page hands the number or record to an open, signed-in softphone tab of
 * the same origin over a BroadcastChannel, then closes. It never dials: the
 * softphone shows the number and waits for the agent to click Call.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var q = new URLSearchParams(location.search);
  var raw = q.get('to') || '';
  // "tel:+91 90000-00011;ext=2" -> "+919000000011"
  var number = decodeURIComponent(raw).replace(/^tel:/i, '').split(/[;?]/)[0].replace(/[^\d+]/g, '').slice(0, 20);
  var record = q.get('contact') || q.get('lead') || '';
  if (!/^(cont|lead)_[A-Za-z0-9]{8,80}$/.test(record)) record = '';
  $('dial-close').onclick = function () { window.close(); };

  if (number.replace(/\D/g, '').length < 6) number = '';
  if (!number && !record) {
    $('dial-number').textContent = 'Not a phone number';
    $('dial-status').textContent = 'This link did not contain a number or a Close contact to call.';
    return;
  }
  $('dial-number').textContent = number || (record.indexOf('cont_') === 0 ? 'A Close contact' : 'A Close lead');

  var channel;
  try { channel = new BroadcastChannel('vobiz-close-dial'); } catch (e) { channel = null; }
  if (!channel) {
    $('dial-status').textContent = 'This browser cannot pass the number to the softphone. Copy it into the softphone\'s dial box.';
    return;
  }

  var id = Math.random().toString(36).slice(2) + Date.now().toString(36);
  var settled = false;
  var notReady = false;
  channel.onmessage = function (e) {
    var d = e.data || {};
    if (d.id !== id || settled) return;
    if (d.type === 'busy') { notReady = true; return; }
    if (d.type !== 'ack') return;
    settled = true;
    $('dial-status').textContent = 'Sent to your softphone. Switch to it and click Call.';
    // Closing works when the browser opened this tab for the link.
    setTimeout(function () { window.close(); }, 1200);
  };
  channel.postMessage({ type: 'dial', number: number, record: record, id: id });

  setTimeout(function () {
    if (settled) return;
    $('dial-status').textContent = notReady
      ? 'Your softphone is open but not ready. Sign in and wait for the green Ready badge, then click the number again.'
      : 'No softphone is open in this browser. Open it, sign in, then click the number again.';
    $('dial-open').hidden = false;
  }, 1500);
})();
