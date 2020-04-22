# Id-manager
Simple OIDC server with Identity management

127.0.0.1:5000/oauth/authorize?client_id=3MEZIcvlhMPiTEcy46spogzg&scope=openid+profile+email+roles:test&response_type=code&nonce=abc&redirect_uri=http://127.0.0.1:9031
127.0.0.1:5000/oauth/authorize?client_id=3MEZIcvlhMPiTEcy46spogzg&scope=openid+email:test&response_type=code&nonce=abc
127.0.0.1:5000/oauth/authorize?client_id=3MEZIcvlhMPiTEcy46spogzg&scope=openid+roles&response_type=code&nonce=abc

curl -u "3MEZIcvlhMPiTEcy46spogzg:POac9Sd4h0mrHZeXN9MljGB6oQRVJenKRnltCyDU10pvfHiX" -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F code=

curl -H 'Accept: application/json' -H "Authorization: Bearer Tu8IQPUjZCoaXElnwQPXvRHDBvOViEUxOD1XuWNH6C" http://127.0.0.1:5000/user-info


@require_role('stock:warehouse[cm|clipper|pf]')


{ stock: {
    admin: []
}

# Flask commands
## Database
flask database init   
flask database seed  

## Client commands
flask client create  
flask client delete  
flask client list  
flask client show  
flask client modify  

## User commands

### Create/delete user
flask user create  
flask user delete <users_id> 

### Show user informatin
flask user list  
flask user show <user_id>  

### Alter user information
flask user modify <user_id>   
flask user password <users_id>   
flask user enable <user_id>  
flask user disable <user_id>   

### Server roles
flask user roles <user_id> add <role>  
flask user roles <user_id> remove <role>  
flask user roles <user_id> all   
flask user roles <user_id> clear  

### client roles
flask user roles <user_id> add <role> for <client>  
flask user roles <user_id> remove <role> for <client>  
flask user roles <user_id> all for <client>  
flask user roles <user_id> clear for <client>  
