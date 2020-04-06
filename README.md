# Id-manager
Simple OIDC server with Identity management

127.0.0.1:5000/oauth/authorize?client_id=3MEZIcvlhMPiTEcy46spogzg&scope=openid+profile+email+roles:test&response_type=code&nonce=abc&redirect_uri=http://127.0.0.1:9031
127.0.0.1:5000/oauth/authorize?client_id=3MEZIcvlhMPiTEcy46spogzg&scope=openid+email:test&response_type=code&nonce=abc
127.0.0.1:5000/oauth/authorize?client_id=3MEZIcvlhMPiTEcy46spogzg&scope=openid+roles&response_type=code&nonce=abc

curl -u "3MEZIcvlhMPiTEcy46spogzg:POac9Sd4h0mrHZeXN9MljGB6oQRVJenKRnltCyDU10pvfHiX" -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F code=

curl -H 'Accept: application/json' -H "Authorization: Bearer Tu8IQPUjZCoaXElnwQPXvRHDBvOViEUxOD1XuWNH6C" http://127.0.0.1:5000/user-info


roles
    - stock
        - connect: basic access 
        - admin: stock admin access
        - warehouse
            - cm: Warehouse C&M access
            - clipper: Warehouse Clipper access
            - pf: Warehouse PF access

@require_role('stock:warehouse[cm|clipper|pf]')


{ stock: {
    admin: []
}