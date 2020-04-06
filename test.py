import re

regex = r"(?:(?:^|\s)roles:(\S+))+"

test_str = "openid profile Jan en roles:wer jee roles:test some other roles:three roles:"

matches = re.findall(regex, test_str, re.MULTILINE)

if matches:
    print('%s matches' % len(matches) )
    for matchNum, match in enumerate(matches, start=1):
        print(match)
else:
    print('no matches')

test_str = "openid profile"
matches = re.findall(regex, test_str, re.MULTILINE)

if matches:
    print('%s matches' % len(matches) )
    for matchNum, match in enumerate(matches, start=1):
        print(match)
else:
    print('no matches')
print('done')

    # print("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum=matchNum, start=match.start(),
    #                                                                     end=match.end(), match=match.group()))
    #
    # for groupNum in range(0, len(match.groups())):
    #     groupNum = groupNum + 1
    #
    #     print("Group {groupNum} found at {start}-{end}: {group}".format(groupNum=groupNum, start=match.start(groupNum),
    #                                                                     end=match.end(groupNum),
    #                                                                     group=match.group(groupNum)))


def match_roles(scope):
    return re.findall(regex, scope, re.MULTILINE)



def generate_user_info(user, scope, ):
    scope_roles = match_roles(scope)
    if scope_roles:
        roles = dict()
        for role in scope_roles:
            user_role = UserRole.query.join(OAuth2Client) \
                .filter(UserRole.user == user, OAuth2Client.client_tag == role) \
                .first()
            roles[role] = user_role.client_roles.split() if user_role else []
        user_info['roles'] = roles
    return user_info
