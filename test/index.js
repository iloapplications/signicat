'use strict';

const should = require('should');
const validator = require('validator');
const chai = require('chai');
const nock = require('nock');
const chaiAsPromised = require('chai-as-promised');
const expect = chai.expect;
const sinon = require('sinon');
const sinonChai = require('sinon-chai');
chai.use(sinonChai);
chai.use(chaiAsPromised);
const Signicat = require('../index');
const urlOptions = {
  protocols: ['https'],
  require_valid_protocol: true,
  require_protocol: true,
  require_tld: false // for localhost
};

const privateJwk = { 
  d: 'Na7lzZR8gTmiJjOnrSew49tT8Qxl7-wFEJAk8_IAKmS1KidtNrNxt5GgBsy7Uksk0EXwYmbxLY7ke_yvGNtDTAaR71VWJyTDYJjiu-D-cMrRWGxLUtf0SDQtuf5_7rVNikmuUgxtaNZowstBZog-W8QIpGv7nvfOKchFK-Cf92ApWWU6DH3vN60TQtk9f8e_XLM4Yy2iBEghU58VNegb8mS9Bg-WfiG8Bf8opjj2IxlssqK98AlXPIZ-T-Xar6D9SkOVYTuracOoxSQjOEKHVCtluGQRinP3yxAQvF81ZPp2zO7LbSx2NRB4h2DzcUXSnMbY2PXgw4Sqs7QlJ7miKgrFyseRgikzZNDLv-8jhujkjRfAZ3VZFPy5-LKtG1uLf8erwwLedCqg9ClTLiXMG05uogdXIB8hYjP04ZWPNR_hQwKAEo3yFsS0SSMBOO4ANjc_uzQf7xmnKei0imDfJcufMFCvPuT_F4x6xJzi_DSLOW8s7KDFvFBTBgnTsoVHIAWDXGXM9iebLx26NwgtUcclfm2hidcsuJnS4Qyx9r-AHjxNH7uVNZP3eyjXqH4jrmweLzOGpSuLIGiXfAi7aVFISH5dD4eaq-zkxZgV-Vs8iRD8TlhYb7ETYxM71fw3Ga-rp9hAHY2_pHz3iCs3yIL08u6CGqe6udB10WmTdjk', dp: 'VYi8AKFAbw0yu5xZcf8MKwQwVSCIqZyw7gZDaz5Exz00XKHVWKlUdvqQH52e9GYW84rqdhCINcXctEnT9kfrUJRp6sg40aFWSfZNGvN0ZlwgHsuk8BKXdD0k8evgEH4iomHk5V6b8Au8ilJN3JlI3mW7ZM4aHqODfPXoNAAwHXNX24hnX3on3Y9xZvEoGZKn4WnU7rGZjcsIYphy3IGfIe0BlZYGTHnteAFjsK0ODXoGXSh2ZvhiDKO6fl57lS_h43i5gLsIOtM-T9uGFFe681h4OcM3HQNcYnwvl0RpdKXIKhVn54w7yKc1e3x6bEO5nj0ZPFwAbLWDZ0ljv_SpOw', dq: 'cqloF7Ips92f75WR2xHAuM7GmpywEWZjdiwbHqDQ79cLFbfQxO99J9kpC9kjTRE4T21OdpHOBtEIQYF8mroEHNtI9guBR1sQwMxx_DHyyJ0M1HHrzBawQr9DqqmqfHNkPCLetwv2E0sOd90CvUU6zL9p0f-Npn4-l1r7KsSAn2w5oDy4fb0ZAn4Lc4GtISYNV9SX9rpZN83WlF1oOzOWenTwiWrQneicRdM5L7HxWBs-FQQX5oi32xSf3chwy9o2po2DUD3Ess5BH-Y0lmDH6hEufwHbKRpKzWLxhZwa0BkbFL68ypbeWK-dUNdh5HCCNup0IpCgP1-_6PnQU-vw9Q', 
  e: 'AQAB',
  use: 'enc',
  alg: "RSA-OAEP",
  kty: 'RSA', 
  kid: 'test',
  n: 'psPFRnGgt4wJK--20KG0M_AgL2B-J0Q4Nrd3duq0lt2kXwtD5MdAmpWpPncQgMzqVT3IyuEjFjHZRw-tv025DbK6PO4k3sZhQwWJjZGte7nKuHzJkQ7tR0ub2DOq4Sg6iBDmBFQ00wotCIfcAbgBT4WLWFu8ne9K4GUjz3vtUCALLryWJeIriJnNl7kKxo8BhbEp567PmECfill9RpPkgm3bp6s2GqAtIwWss6hYY02GPm_cssFwLl_fRBzQcFxg30i3oMgg-Xj5flewEC8sdPXdzXg9PJTLmppfKdnYtgPCTR8a2mTgy_B8vXXrkX636qk_FaT9C0QWxMg6fII_5vqRdx65uAVWqc69bm0ikSz_PgnK5flkwLRQr4D5CvZNCw7xngrEBTP42O0mjtbQJZPYzF3__pdpwqli1Ja1WNEC0EZtzi_2xs7rn07qVv2ZeQ0mObp4gs2uyflQZ-6Mv7S2MnJ00Bn7M_kl6S9a1jRHQDnCe61yfgQr8oGvfI7jaiN-8IMphzdkpK4nO4euWk8M5XQFpIorVyLT2RtIUQlA4L6GQBBuixZxI7nt2AA9ZA4J5cTukYGqT908NJ3g8HEpbWvuZ8kFOXAVi8EJqN9OFDXB5qPDfXFZ6lH7-UmYPKLOjrscX9LUSz_Onu65SVJlylHqorkK0mVOQgo7oaM', 
  p: '00FDBBfSFIbQYJ8yOCJ7c6ZPLmJxQ7_Fch01KdHJvKjKinb5dDtJMxgZzKwPudBajJWE4ucVMuRYRv4QMJWXov6CaLKN-SHkMFIwWMN-UJAVGT7e_iIq1_BrvFvTeFY9zshpuyFiP4lDNzPH1xX2aD0lCt42l-1rfScm1LIO0LYy1Qqma6m-aaKLAcBpr-6SM3A7-YqNVP3enZevPTz6rgZ_boKICVdR-a3vLNb5w1sP_18I3Fcb0vGCsoxuNh46DaDdSs2jkwPmIrra040vstoXHjOLzlubrrH69WqkbNtHf1DRcKgh7fzgHwuzovC6Bn142cdCmr9aLyVgExFUNw', 
  q: 'yhYlTst5WmxYynEtYU9GBqysQnjJSh1gDKocbJv_7AHdfIMnK8tHdqEByj9DPgao76yZt1fGSN9v1B3PhVYYrhdLvtksdYjUgnu0vjtg7kHsDxwY6H4nZykxWr1tjcWHHmcUnlWU_vtkg1pES8_WJ-dtH0IYe0luPRqVqs8YYKL6He-pRbPj4YJJ6KtYgYFpSKbS3hGHDeEo_Bwz9-cP6Q6NxJwgeOZz8BtryHo4gh77RapZcpxH320Fw993xYewpAt_Bi7OqasH8-DwxMSxK-VuAjgfokxZMX2rQXLGO8xVRTVmXGbAK7deWuvlO1qgCHVxZswzI1aNyMjQ4ze_9Q', 
  qi: 'nh4sH934RRsFA_T68m0sas6i9NaRYLOYHiK-Z4QUHxpG4lXVM1Q80srDWTYX_bGCa6R2xLTnYkICN4Y3vnUFxbfD4iBRKGdmepegF7jajbBAqCpCHDRTJUisd6MF--VOy-HPB2uIpDRw2X-g01k-AEqy7sXu1YEfh9_jEBf2JXV86mylJEqWJJT4zEtu18pq1ZV157-dLezHt1IZ9VJJldXgj1ZQza8T-15vQFfiwx1vLKZI3YiRlYVPEhCSfSqFh1C6Im9vQ8R_4kymnzDXJirzZZPJKr0FoFlJEUX8mFMCHrhqi0-OSMrCRxci_40Gtd08qo40iWjid0szYeAjfA' };

const postAccessTokenSuccessResponseDef = {
  access_token: 'eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJXUGRQY3JiRWtvN0luR2p2UVBVbWRIVGdWTkk2S0tWbyIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIl0sInNubSI6ImRlbW8iLCJpc3MiOiJodHRwczpcL1wvcHJlcHJvZC5zaWduaWNhdC5jb21cL29pZGMiLCJleHAiOjE1NTk1Nzc2NTIsImlhdCI6MTU1OTU3NTg1MiwianRpIjoiMEpoUE9UV2RaOXFaLTVsTldjMUhMSDVHOGdQNVItNi0iLCJjaWQiOiJkZW1vLXByZXByb2QifQ.gzFQtc3N03kxo4peJH5WQQ0oEO5JNLiQInlh4ji4vk1SRKL-gWi3gwrsprQKUJQHU8GfQ4Jb7tbc9Zm73DfeX29oljd8GwRncuX1MNkvqqYVHhdNv4s43SG8-UGrRsNxlAKjkUbV5TsFXdiRLOyVwUn23h9E6AnrB4bS_d9ZgDsj6OU8CrA5tkbeBQWNfF4K_TaBMOMT2F0AZCmV0CzKffN-qTo6_PVO0QRc5x6kmmebiee4iHal3OwyMb3FugUrvcwlXex5YWDVQHijZ4Vb2ipqZl9_VYwoiBWbgRtd-Qb6E3uvJv8Nk-pmQD4O7rLIiYYU_3NgNoT7cTM7CzaXAA',
  token_type: 'Bearer',
  refresh_token: 'axvnUk8PAx1Bf-epuwQWXXv2grnprZPr',
  scope: 'openid profile',
  expires_in: 1800,
  id_token: 'eyJraWQiOiJhbnkucHVibGljIGtleSBmb3IgZnRuIGZ1bGwgZW5jcnlwdGlvbiB0ZXN0Mi50ZXN0Lmp3ay52LjIiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAifQ.gadyn1mDOXvQRgacRcB3sLc7v3nziXgvIZkXn4ywAQ_kA7ASCx8TpikdoLI2FbkkN1C8S0T6BJBfYgwgRX2dujxuv-rgg_umrIzVihhXRMkuR4HQraC3K8Aiw_zNP4-2Ge5z-FcJU82z1XP_xtcjCOkqjrluYVXEJ_HzC3cPkbRLnzyc9TdKlmSga0LWJmTlr5dLkXjfY4r4Z4Gh09k4r1OTLMtqKePPeGsNRBAN33SGIoafkNczNUAbfvZ4Bw3Eu9XM1KoUBRGwQ_ZNfendzR0FYOATUfia3iFmxIDyN8YTbfu9cA3yq6d7euPMC0wMDzNInUfWNAKqxNVTOukcwCRaLVcfcBnmDJLBk7w8SMj_GgSZJEENNC6Aw48vGrJpleUf6Pfefm7gY-eGyTRBwtptC3daAziIKiPsm7ljqLrHmDkrcwF_qvZQP7zbVG1tctPidzYOoKBXiXetsaCv2hYq4MfZrWX8Z1DzqL97qZIo9lqVPvCfHVL_qSC-hJZ2mJqbuG_Ct38JN1ryM9TT1nlh9P-e9Jib2kJeFMCo6PQgIQhLAqNfS0cLyPItq_43K20ljFBKBF_NNPd3V-pq-tPVG5aJ_kqUuzUi_IamgyOSewqNX53SsoO7yvV5PZH8tge5iBNN8hnWkTNi-lrzHKF08TqolQHeI7RKFysPqH0.U7sNGekGtqRVMtaelVRlNg.ImOW0oi4BZ-eRHM1CM2_2t8f0gKb_MZwV7olt5l7iFYRkr-Gr3AIxe2LRgNSJyTIT10oJFLZUVImt88Z3HjvmdJoSpSP7kqFGjvZXqOMHxnDqCLvrLQ5DldUEPx5VmpDGfNHEEi29NREz-J8Z0OWQ_fs8f-jebtmYo_CLQIRSteGKbf2_YwhklkaT5VPS-Lapcgbbc-5QOtGbhW1w8t-fWy5OQmj91z6hzvwTZChEhmQcM2oVXG8xRnpXCp_kIiphN9F3HOsuq8BlawBFmwKXaW4-1tepdRVsaQWavJr8enJkYLgAL1AztJh6NgdakhcaZmDdMtCnY857zZA2n9X8Gbzh-NhJze4I_L2wMglEg5m2-Yl7FlYF_emzkLiXHagVXbKn2I9ltXZJWX_I1X7t-p0laAiO44RI1NnFYUU8W5exYzXWaNR9KK3Ey2wExnG08RxLTGkkJ7Wo1762RYupvdszlYy40AHG_0Gy7K-7i3-sCVnW7KjYGOp_AaW3BU7QcdGUmpGFbAIz80e9MsGuVzWqjcBOdimzkucn4YJuPzRrGIWx1cN19a_dkhZiDY6a7ESxZLAEda9tlXHvU14Dc3GdilxLo__3neS-KnCICRr19U3XHQUMFM1w2TwKm_SnGcaphmX-sos0YSv8FGzilP6Ox0Ufjmjsz4lBqmqfukWUMMoHoqJ4BzBxy28nEUr12aJ3vF7IW_2LtQQcoHH7fLrm9CSdqqp3DheWacUu3XiuGzI0JdVe36M1T1PpGhci6pQXLHVfAaFat7glOD4zuYdUsv8Lkl0OnWwm6D3L95teH7StIdTVyL_vCdoIEDxEFdUcl6tgqocahL7VXl5kIYwwWQTO2kXLb3NDH4nQw0Je7h-fg7adXujxlF0ukpVUgpmlOJqW7jqI5VkWfrwIXyVbU_lhoQHXHEYSEElMtcFRgDUQB08vaWttxEWyDsYVEbKRemqDNnsappcLRl4ACgJa4k4_IH08mavC7YDvxFS4XGGKboGgeLtbGSGPSbHOaKmcNJsrD5mYdGHULOyWIr0oCjBEOXa6G-NlzFbSUr8xu9vf1NPqpr0Tf8bBKi3FLxZnfiiIG6yM8CeMGP7ao8noO79v4AQF6CmpvZQOzPhDFqQxYr5i41xX8JKE_my.gifT-v3pJgrX4ycU2DEyhA'
};
let postAccessTokenSuccessResponse = { ...postAccessTokenSuccessResponseDef }; // clone

const userInfoResponse = 'eyJraWQiOiJhbnkucHVibGljIGtleSBmb3IgZnRuIGZ1bGwgZW5jcnlwdGlvbiB0ZXN0Mi50ZXN0Lmp3ay52LjIiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAifQ.m0jUmqUVe3krCZYm2hGsQOGu6rAxohubyrzmbbLBzBquLSiLY7N4Zi5ljC7UO_8C1i2_CGzuw8yVmES6fyeYNrjdrMgwE5FrzuzI0AjvPlZl42wMqw6nfZYhA54rpOvugDuxpCBVWdwdi4QJlnJAvmNoTu7eV9vcDucs3trX3fQNiO1oDQyXtb5izvMuJD4ZELmOqm5N8MfGX8IK5Nce99MJcURBtvP-mQcjlk8drnOHy9V2Dmx794e_bGJGW3tWo-_wm9NpAG_oPURvd0Lz7kzFhoqdGvf_bPbtIS2r-BMOWi-xWFfwL0TMzAJqwyFrgYZ-tuQgHW70lm0PqT98AdDIvVRwETizdzZmEPwHmiyWqZr46b5NGkjAqTHNnjUCdFJZB-IFivezNKH7nIGAApOk_z_qtascR9R1Sdszw1rnJtC1FgTVn4VLIHmzneh1I9O75QqIEpNocfVLLcsdf3MZPFLZiC2rR_EseVAKsnI7S3oQLxQCgGhlu6FRh6VYWv-xymcfBX9BAg3588HQYR704WZsSgjBfUbrMZLqSrxK7sqTdmIkQ2irUNSN6ak8RD67FbzMepLBro1dF68LdsjQbF2LRce2TtWyBzHpvk0XFfgWY9yYTUnRvM3qntZbwcqIYfRbUaFnXnEfQ0wIqHXRw3xSR7PIVNLTSDRf7Ss.z2joF5mQD-B4Fg8-uhoscg.smhR8D_2eW25Q8jfG-c9-XOSP_FJC_GHMiZ3uKh_799I0d_THAQm6RaXU3wXMhtAu6PLxCDgxD9MDj8h770xKFlJ98K381dLnYRFXnCYyXuonnLOoEJAfcB1r44Motjk8Vv3IOZxgMtjQUOxVvDYjSsT5B6Up9C5W0BLxXk89mk_-gRAqOojfREgmdtdVGR8mzuvaWtZ8GZ-8iqAQuI0kNaoL7Jm5RVoVOWj-V7OwtYLlCS6aymsfOsKtU5Ly7x3AOKO2BWWWNbL_oVTttUqZxpTt7Ft8Mtw02x6TaAehQ8aQNwKFpewHJjuHZAF0nVvd4JPcra3Gchas-zlwEHOx8TyDFlaLWuAFG-59yfUr9JPZvlEQV4u848m8lk9_v3U6o0lIJKzkmVZH12j_LMAzb4MeknH7m8X8MJcEmXncb5AVKjQ710OhCXm4w0DmiU2Yx17uyNoqTM0wZRtbHhyg4w4K4dY_jaqHbkekYaWsbXBakiOgyyHVMA5g9NmfHUiXNdes_G6GyEvI38ZhecB6fRZ1YA0iPbYaWSLQorHA5N3KEiWVrPC_KzWhZ5R_RBnd27XdxgiraUEgKZg-nS_WpUi_MfHTrQTfzfhgjWFWejMum3o67oAH_eclk857gfYq-SgoQ7O23j9VEOrFVaWAjJWVMsrRkilsMZI3LsoFE8eA75oF1wjrz571RamciQk8Qag-WZLmkqXvd6W4YsVnx-qVrerwvMDuHQxXk1vi6BdnbKlKoR4qrv0Owq8-KoX-48xcITeK8h4r9IqSGv1mENIDakXBLsYbr44kZtZR4c.O0RbL5oh716_qcFExNe7pA';

const decryptedUserInfo = {
  sub: '1vryYlbbL8ZEucdMBPtt-U_xhRxTeXJg',
  name: 'TESTAA PORTAALIA',
  given_name: 'PORTAALIA',
  locale: 'FI',
  family_name: 'TESTAA'
};

const pubKeysResponse = {
  keys: [
    { kty: 'RSA', e: 'AQAB', use: 'sig', kid: 'preprod.signature-oidc-hsm.jwk.v.1', alg: 'RS256', n: 'px6mGAGqVTcf8SNBzGF5ZzMQem8QH2wXO1xXEgwQAsBCcVvlpliIj1gkPDux36DYAgdUYy1wM7VhW6FHNhT1yCA7aYteUKB9hKAai3wzQNoUXPHQlKQsWRgTboFRQrkKzPgHHIp8IwZxBFzjCp9W9gdQ_LIQyCyjxoRTR0yg21HB1SC2bh91L2K689IpS9qcb7KBjizVmGqwRCgWtA1lBOKEpgrhPeHnSLcvRWG97ePR5MfmzftWxRftWIlDaIWV_3cnn8WsXH2Qtg4cq5FGBdS30SWHTpYNRuLYfvttivR1uZmx8fnnYEfy3L7lxHbWuVbdkySofQ7yvJWX56GGJw' }, 
    { kty: 'RSA', e: 'AQAB', use: 'enc', kid: 'any.oidc-encryption-preprod.test.jwk.v.1', alg: 'RSA-OAEP', n: 'ou9ZQ_e0JSMhOA3fSwzH4h9OHgS8xLbtScHUlQEq9XWRw0i5ZefGWEUCeWJgehxuRMumPdm5_csfSnJLJom3c5cEnloXB53ZFEa6qJ7AEHnSjdMxnIkzcq_4ICQg69fwTac1ZCjxhCraUs6G9LE8b9gN-EHmd8MXuLRxZUkjlgiQKb-XhfDaDA7rd7KMczyxrieZT3q5lk1fjw2V_o_jasowLo8i7s8Wa4S7BAg1ZFv2-oc8PcobbJLsAAIxg3PEn0nDIvNcs6cjjYje2_TrrXMmis2TJquQhLOHjx_yQdzQNfzxC5_GwOZPBKZR1gH1-QxlW7q8jevC2-f_-7FlHw' }
  ]
};

const userInfoSuccessResponse = {
  sub: 'bob',
  groupIDs: ['bobsdepartment', 'administrators'],
  given_name: 'Bob',
  name: 'Bob Smith',
  email: 'bob@mycompany.com',
  phone_number: '+1 (604) 55-555-66-777',
  address: { formatted: '123 Main St., Anytown, TX 77777' },
  picture: 'http://mycompany.com/bob_puoto.jpg'
};

let config, authorizeParams, tokenParams, userInfoParams;
beforeEach(() => {
  config = {
    client_id: 'demo-preprod',
    secret: 'mqZ-_75-f2wNsiQTONb7On4aAZ7zc218mrRVk1oufa8',
    isProd: false,
    FTN: false
  };
  authorizeParams = {
    response_type: 'code',
    scope: 'openid+profile',
    redirect_uri: 'https://example.com/redirect',
    state: '123abc',
    nonce: 'sessionId',
    acr_values: 'urn:signicat:oidc:method:idin'
  };
  tokenParams = {
    code: 'SplxlOBeZQQYbYS6WxSbIA',
    redirect_uri: 'http://example.com/redirect',
    grant_type: 'authorization_code'
  };
  userInfoParams = {
    access_token: 'eyJraWQiOiJhbnkub2lkYy1zaWduYXR1cmUtcHJlcHJvZC50ZXN0Lmp3ay52LjEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJXUGRQY3JiRWtvN0luR2p2UVBVbWRIVGdWTkk2S0tWbyIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIl0sInNubSI6ImRlbW8iLCJpc3MiOiJodHRwczpcL1wvcHJlcHJvZC5zaWduaWNhdC5jb21cL29pZGMiLCJleHAiOjE1NTk1Nzc2NTIsImlhdCI6MTU1OTU3NTg1MiwianRpIjoiMEpoUE9UV2RaOXFaLTVsTldjMUhMSDVHOGdQNVItNi0iLCJjaWQiOiJkZW1vLXByZXByb2QifQ.gzFQtc3N03kxo4peJH5WQQ0oEO5JNLiQInlh4ji4vk1SRKL-gWi3gwrsprQKUJQHU8GfQ4Jb7tbc9Zm73DfeX29oljd8GwRncuX1MNkvqqYVHhdNv4s43SG8-UGrRsNxlAKjkUbV5TsFXdiRLOyVwUn23h9E6AnrB4bS_d9ZgDsj6OU8CrA5tkbeBQWNfF4K_TaBMOMT2F0AZCmV0CzKffN-qTo6_PVO0QRc5x6kmmebiee4iHal3OwyMb3FugUrvcwlXex5YWDVQHijZ4Vb2ipqZl9_VYwoiBWbgRtd-Qb6E3uvJv8Nk-pmQD4O7rLIiYYU_3NgNoT7cTM7CzaXAA'
  };
});

const apiUrl = 'https://preprod.signicat.com';

describe('Signicat', () => {
  describe('Constructor', () => {
    it('Should return an error when client_id is missing', () => {
      delete config.client_id;
      expect(() => new Signicat(config)).to.throw(Error, /client_id/);
    });
    it('Should return an error when secret is missing', () => {
      delete config.secret;
      expect(() => new Signicat(config)).to.throw(Error, /secret/);
    });
    it('Should return an error when isProd is not a valid boolean', () => {
      config.isProd = 'true';
      expect(() => new Signicat(config)).to.throw('Configuration: isProd must be a boolean');
    });
    it('Should return an error when FTN is enabled and privateJwk is not provided', () => {
      config.FTN = true;
      expect(() => new Signicat(config)).to.throw('Configuration: privateJwk is required when FTN is enabled');
    });
    it('Should use Staging apiUrl when isProd is disabled', () => {
      config.isProd = false;
      expect(new Signicat(config).apiUrl).to.equal('https://preprod.signicat.com/oidc/');
    });
    it('Should use Production apiUrl when isProd is boolean:false', () => {
      config.isProd = true;
      expect(new Signicat(config).apiUrl).to.equal('https://id.signicat.com/oidc/');
    });
  });

  describe('Get Authorization endpoint request', () => {
    it('Should return an error when no parameters are sent', () => {
      expect(new Signicat(config).getAuthorizationUrl()).to.be.rejectedWith(Error);
    });
    it('Should return an error when state is missing', () => {
      delete authorizeParams.state;
      expect(new Signicat(config).getAuthorizationUrl(authorizeParams)).to.be.rejectedWith(Error, /state/);
    });
    it('Should return an error when scope is missing', () => {
      delete authorizeParams.scope;
      expect(new Signicat(config).getAuthorizationUrl(authorizeParams)).to.be.rejectedWith(Error, /scope/);
    });
    it('Should return an error when response_type is missing', () => {
      delete authorizeParams.response_type;
      expect(new Signicat(config).getAuthorizationUrl(authorizeParams)).to.be.rejectedWith(Error, /response_type/);
    });
    it('Should return an error when redirect_uri is missing', () => {
      delete authorizeParams.redirect_uri;
      expect(new Signicat(config).getAuthorizationUrl(authorizeParams)).to.be.rejectedWith(Error, /redirect_uri/);
    });
    it('Should return an error when redirect_uri is not a valid HTTP Url', () => {
      authorizeParams.redirect_uri = 'http://example.';
      expect(new Signicat(config).getAuthorizationUrl(authorizeParams)).to.be.rejectedWith('Validation: redirect_uri must be a valid http URL');
    });

    // More info: https://developer.signicat.com/documentation/authentication/protocols/openid-connect/full-flow-example/
    it('Should return a valid authorization URL with signicat Full-flow example parameters', async () => {
      const resultUrl = apiUrl + '/oidc/authorize' +
        '?client_id=demo-preprod' +
        '&response_type=code' +
        '&scope=' + encodeURIComponent('openid+profile') +
        '&redirect_uri=' + encodeURIComponent('https://example.com/redirect') +
        '&state=123abc' +
        '&nonce=' + encodeURIComponent('sessionId') + 
        '&acr_values=' + encodeURIComponent('urn:signicat:oidc:method:idin');

      const result = await new Signicat(config).getAuthorizationUrl(authorizeParams);
      expect(result).to.equal(resultUrl);
    });

    // More info: https://developer.signicat.com/documentation/authentication/protocols/openid-connect/endpoints/
    it('Should return a valid authorization URL with signicat example authorization request parameters', async () => {
      const resultUrl = apiUrl + '/oidc/authorize' +
        '?client_id=demo-preprod' +
        '&response_type=code' +
        '&scope=' + encodeURIComponent('openid+profile+email') +
        '&redirect_uri=' + encodeURIComponent('https://server.example.com:443/oidcclient/redirect/client01') +
        '&state=' + encodeURIComponent('af=ifjsldkj') +
        '&nonce=' + encodeURIComponent('sessionId') + 
        '&acr_values=' + encodeURIComponent('urn:signicat:oidc:method:scid-proof') +
        '&login_hint=deviceId-92855960' +
        '&login_hint=authType-email';

      authorizeParams.scope = 'openid+profile+email';
      authorizeParams.redirect_uri = 'https://server.example.com:443/oidcclient/redirect/client01';
      authorizeParams.state = 'af=ifjsldkj';
      authorizeParams.acr_values = 'urn:signicat:oidc:method:scid-proof';
      authorizeParams.login_hint = ['deviceId-92855960', 'authType-email'];
      const result = await new Signicat(config).getAuthorizationUrl(authorizeParams);
      expect(result).to.equal(resultUrl);
    });
  });

  describe('POST access token request', () => {

    beforeEach(() => {
      nock(apiUrl).post('/oidc/token').reply(200, postAccessTokenSuccessResponse);
    })

    it('Should return an error if redirect_uri is not a valid HTTP URL', () => {
      delete tokenParams.redirect_uri;
      expect(new Signicat(config).postAccessToken(tokenParams)).to.be.rejectedWith(Error, /redirect_uri/);
    });

    it('Should return an error if no code sent', () => {
      delete tokenParams.code;
      expect(new Signicat(config).postAccessToken(tokenParams)).to.be.rejectedWith(Error, /code/);
    });

    it('Should return an error if no grant_type sent', () => {
      delete tokenParams.grant_type;
      expect(new Signicat(config).postAccessToken(tokenParams)).to.be.rejectedWith(Error, /grant_type/);
    });

    it('Should return a valid access_token', async () => {
      const result = await new Signicat(config).postAccessToken(tokenParams);
      expect(result).to.eql(postAccessTokenSuccessResponse);
    });
  });

  describe('GET User info request', () => {

    it('Should throw an error if no params provided', () => {
      expect(new Signicat(config).getUserInfo()).to.be.rejectedWith(Error);
    });

    it('Should throw an error if access_token is missing', () => {
      delete userInfoParams.access_token;
      expect(new Signicat(config).getUserInfo(userInfoParams)).to.be.rejectedWith(Error, /access_token/);
    });

    it('Should return user info with valid access_token', async () => {
      nock(apiUrl).get('/oidc/userinfo').reply(200, userInfoResponse);

      const result = await new Signicat(config).getUserInfo(userInfoParams);
      expect(result).to.eql(userInfoResponse);
    });
  });

  describe('GET JWK public keys', () => {
    it('Should return an error if public keys can not be fetched', () => {
      nock(apiUrl).get('/oidc/jwks.json').reply(200, {});
      expect(new Signicat(config).getPublicKey('enc')).to.be.rejectedWith(Error);
    });

    it('Should return enc public keys', async () => {
      nock(apiUrl).get('/oidc/jwks.json').reply(200, pubKeysResponse);

      const result = await new Signicat(config).getPublicKey('enc');
      expect(result).to.eql(pubKeysResponse.keys.find(obj => obj.use === 'enc'));
    });

    it('Should return sig public keys', async () => {
      nock(apiUrl).get('/oidc/jwks.json').reply(200, pubKeysResponse);

      const result = await new Signicat(config).getPublicKey('sig');
      expect(result).to.eql(pubKeysResponse.keys.find(obj => obj.use === 'sig'));
    });
  });

  // More info: https://developer.signicat.com/documentation/finnish-trust-network/full-message-level-encryption-for-ftn/
  describe('Get Authorization endpoint request with Full Message-level Encryption', () => {

    beforeEach(() => {
      nock(apiUrl).get('/oidc/jwks.json').reply(200, pubKeysResponse);
    });

    it('Should return a valid authorization URL with signicat Full-flow example parameters', async () => {
      authorizeParams.scope = 'openid';
      authorizeParams.redirect_uri = 'https://labs.signicat.com/redirect';
      authorizeParams.acr_values = 'urn:signicat:oidc:method:ftn-nordea-auth';
      config.FTN = true;
      config.privateJwk = privateJwk;
      const resultUrl = await new Signicat(config).getAuthorizationUrl(authorizeParams);
      expect(validator.isURL(resultUrl, urlOptions)).to.equal(true);
    });

    it('Should return a valid authorization URL with signicat example authorization request parameters', async () => {
      authorizeParams.scope = 'openid';
      authorizeParams.redirect_uri = 'https://labs.signicat.com/redirect';
      authorizeParams.state = 'af=ifjsldkj';
      authorizeParams.acr_values = 'urn:signicat:oidc:method:ftn-nordea-auth';
      authorizeParams.login_hint = ['deviceId-92855960', 'authType-email'];
      config.FTN = true;
      config.privateJwk = privateJwk;
      const resultUrl = await new Signicat(config).getAuthorizationUrl(authorizeParams);

      expect(validator.isURL(resultUrl, urlOptions)).to.equal(true);
    });
  });

  describe('Get access token with full Message-level Encryption', () => {
    beforeEach(() => {
      postAccessTokenSuccessResponse = { ...postAccessTokenSuccessResponseDef }; // clone original
    });

    it('Should throw an error if can not verify id token signature', () => {
      postAccessTokenSuccessResponse.id_token = 'fasdfas';
      config.FTN = true;
      config.privateJwk = privateJwk;

      nock(apiUrl)
        .get('/oidc/jwks.json').reply(200, pubKeysResponse)
        .post('/oidc/token').reply(200, postAccessTokenSuccessResponse);

      expect(new Signicat(config).postAccessToken(tokenParams)).to.be.rejectedWith(Error);
    });

    it('Should verify id token signature and return access_token', async () => {
      config.FTN = true;
      config.privateJwk = privateJwk;

      nock(apiUrl)
        .get('/oidc/jwks.json').reply(200, pubKeysResponse)
        .post('/oidc/token').reply(200, postAccessTokenSuccessResponse);

      const result = await new Signicat(config).postAccessToken(tokenParams);
      delete result.nonce;
      expect(result).to.eql(postAccessTokenSuccessResponse);
    });
  });

  describe('Get User info with full Message-level encryption', () => {

    it('Should decrypt and verify signature from JWE userinfo token', async () => {
      config.FTN = true;
      config.privateJwk = privateJwk;

      nock(apiUrl)
        .get('/oidc/jwks.json').reply(200, pubKeysResponse)
        .get('/oidc/userinfo').reply(200, userInfoResponse);

      const result = await new Signicat(config).getUserInfo(userInfoParams);
      delete result.ssn;
      expect(result).to.eql(decryptedUserInfo);
    });
  });
});
