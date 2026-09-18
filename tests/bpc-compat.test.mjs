import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBpcCompatibilityScript,
  getBpcLocalScriptNameForURL,
} from '../src/runtime/bpc-compat.js';

test('selects BPC local script language using the extension dispatcher rules', () => {
  assert.equal(getBpcLocalScriptNameForURL('https://www.lemonde.fr/story'), 'fr');
  assert.equal(getBpcLocalScriptNameForURL('https://www.handelsblatt.com/story'), 'de');
  assert.equal(getBpcLocalScriptNameForURL('https://www.elpais.com/story'), 'es.pt');
  assert.equal(getBpcLocalScriptNameForURL('https://www.ilsole24ore.com/story'), 'it');
  assert.equal(getBpcLocalScriptNameForURL('https://www.example.com/story'), 'en');
});

test('builds a document-start script with the BPC payload and runtime shim', () => {
  const script = buildBpcCompatibilityScript('https://www.lemonde.fr/story', {
    bpc: true,
    csBlock: true,
    csClearLocalStorage: true,
    csParam: { article_sel: 'article' },
  });

  assert.match(script, /localScript: "fr"/);
  assert.match(script, /cs_param/);
  assert.match(script, /cs_clear_lclstrg/);
  assert.match(script, /getExtFetch/);
  assert.match(script, /chrome/);
});
