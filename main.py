
import argparse
import yaml
import json
import requests
import copy
import jsonpatch
import re
import dict_helpers

# args
parser = argparse.ArgumentParser()
parser.add_argument("--config", type=str, help="config file",
        default='/opt/gravitee_manager/conf/gravitee_manager.yaml', required=False)
parser.add_argument("--dry-run", action="store_true", help="only output of changes",
                    required=False)
parser.add_argument("--remove-api", action="store_true", help="APIs on Gravitee server\
        that are not found in config will be deleted", required=False)
args = parser.parse_args()

# parse configs
with open(args.config, 'r') as f:
    conf = yaml.load(f, Loader=yaml.SafeLoader)

# parse templates of API
with open('templates/api.json') as api_json, \
        open('templates/groups.json') as groups_json, \
        open('templates/plans.json') as plans_json, \
        open('templates/flows.json') as flows_json:
    api_tpl = json.load(api_json)
    groups_tpl = json.load(groups_json)
    plans_tpl = json.load(plans_json)
    flows_tpl = json.load(flows_json)

# vars
headers = {'Authorization': 'Bearer ' + conf['auth_token']}
url = "{0}/management/organizations/{1}/environments/{1}".format(
        conf['api_host'], conf['organization'])
errors = 0

def curl_api(args, method='get', body={}):
    global errors
    timeout = 10
    bad_code = 0
    try:
        if len(body) != 0 or method == 'post':
            headers['Content-Type'] = 'application/json;charset=UTF-8'
            if method == 'put':
                req = requests.put(url=url + args,
                                    headers=headers, json=body, timeout=timeout)
                if req.status_code != 200:
                    bad_code = 1
            else:
                req = requests.post(url=url + args,
                                    headers=headers, json=body, timeout=timeout)
                if req.status_code not in (200, 201, 204):
                    bad_code = 1
        elif method == 'delete':
            req = requests.delete(url=url + args, headers=headers, 
                                  timeout=timeout)
            if req.status_code != 204:
                bad_code = 1
        else:
            req = requests.get(url=url + args, 
                                  headers=headers, timeout=timeout)
            if req.status_code != 200:
                bad_code = 1
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    
    if bad_code != 0:
        print("ERROR: url=\"{0}\", code=\"{1}\"\nResponse: {2}".format(
                url + args, req.status_code, (req.text or 'none')))
        result = 0
        errors += 1
    else:
        try:
            result = req.json()
        except ValueError as e:
            result = None
    return(result)

def publish_deploy_api(result_api, api):
    def gen_api_patch(result_api, api):
        cleared_api = dict_helpers.remove(result_api, ('id',), ('deployed_at',), ('created_at',), ('api',), 
                         ('updated_at',), ('published_at',), ('picture_url',), ('background_url',))
        return(jsonpatch.make_patch(cleared_api, api))

    patch_api = gen_api_patch(result_api, api)
    if patch_api:
        print("Changes on Gravitee server for API \"{0}\":\n  {1}".format(
            api['name'], patch_api))
        
        # Create or remove plan(s) in API
        if args.dry_run == False:
            for i in patch_api:
                if 'path' in i and re.match(r'^/plans/', i['path']):
                    print("Redeploy plan(s) for API \"{0}\"".format(api['name']))
                    if result_api['plans']:
                        for plan in result_api['plans']:
                            print("  Delete plan \"{0}\" for API \"{1}\"".format(
                                plan['name'], api['name']))
                            if curl_api('/apis/' + result_api['id'] + '/plans/' + plan['id'],
                                        method='delete') == 0:
                                return(0)
                    for plan in api['plans']:
                        print("  Create plan \"{0}\" for API \"{1}\"".format(
                            plan['name'], api['name']))
                        if curl_api('/apis/' + result_api['id'] + '/plans', body=plan) == 0:
                            return(0)

                    result_api = curl_api('/apis/' + result_api['id'])
                    patch_api = gen_api_patch(result_api, api)
                    break
                
            print("Publish API \"{0}\"".format(api['name']))
            result_for_publish = jsonpatch.apply_patch(result_api, patch_api)
            if curl_api('/apis/' + result_api['id'], body=result_for_publish,
                        method='put') == 0:
                return(0)

            print("Deploy API \"{0}\"".format(api['name']))
            if curl_api("/apis/{0}/deploy".format(result_api['id']),
                        method='post') == 0:
                return(0)
    else:
        print("Nothing to change in API \"{0}\"".format(api['name']))

def main():
    for api_conf in conf['apis_config']['apis']:
        print("\nProcessing of \"{0}\" API...".format(api_conf['name']))
    
        # Generating the API config in "api" variable
        api = dict_helpers.deep_merge(api_tpl, api_conf)
        if 'entrypoints' not in api_conf or 'virtual_hosts' not in api_conf['proxy']:
            api['entrypoints'] = [{'target': 'https://api.company.com' + api_conf['context_path']}]
            api['proxy']['virtual_hosts'] = [{'path': api_conf['context_path']}]
        
        api['proxy']['groups'] = [dict_helpers.deep_merge(groups_tpl, group) for group in api_conf['proxy']['groups']]
        for group in api['proxy']['groups']:
            for endpoint in group['endpoints']:
                endpoint.update(dict_helpers.deep_merge(groups_tpl['endpoints'][0], endpoint))
        
        if api['plans'] == []:
            api['plans'] = [plans_tpl]
        else:
            api['plans'] = [dict_helpers.deep_merge(plans_tpl, plan) for plan in api_conf['plans']]
        
        if api['flows'] != []:
            api['flows'] = [dict_helpers.deep_merge(flows_tpl, flow) for flow in api_conf['flows']]

        # Update or create API  
        api_info = curl_api('/apis?name=' + api_conf['name'])
        if api_info != 0:
            if len(api_info) != 0:
                result_api = curl_api('/apis/' + api_info[0]['id'])
            else:
                print("\"{0}\" API not found, started to create".format(api_conf['name']))
                if args.dry_run == False:
                    req_api_create = {
                        'name': api['name'],
                        'contextPath': api['context_path'],
                        'endpoint': api['proxy']['groups'][0]['endpoints'][0]['target'],
                        'description': api['description'],
                        'version': api['version'],
                        'gravitee': api['gravitee']
                    }
                    result_api = curl_api('/apis', body=req_api_create)
                    if result_api == 0:
                        continue
            
                    print("Start API \"{0}\"".format(api_conf['name']))
                    if curl_api("/apis/{0}?action=START".format(result_api['id']),
                                method='post') == 0:
                        continue

            if publish_deploy_api(result_api, api) == 0:
                continue

    # Deleting APIs on Gravitee server that are not found in config
    if args.remove_api == True:
        apis_from_gravitee = curl_api('/apis')
        if apis_from_gravitee != 0:
            for api in apis_from_gravitee:
                if not any(api['name'] == i['name'] for i in conf['apis_config']['apis']):
                    print("\nAPI \"{0}\" not found in gravitee_manager config".format(api['name']))
                    if args.dry_run == False:
                        if api['state'] != 'STOPPED':
                            print("Stopping API \"{0}\"".format(api['name']))
                            if curl_api("/apis/{0}?action=STOP".format(
                                api['id']), method='post') == 0:
                                continue

                        if api['lifecycle_state'] != 'DEPRECATED':
                            print("Deprecate API \"{0}\"".format(api['name']))
                            result_api = curl_api('/apis/' + api['id'])
                            if result_api == 0:
                                continue

                            result_api['lifecycle_state'] = 'DEPRECATED' 
                            if curl_api('/apis/' + result_api['id'],
                                        body=result_api, method='put') == 0:
                                continue

                        print("Deleting API \"{0}\" on Gravitee server".format(api['name']))
                        if curl_api('/apis/' + api['id'], method='delete') == 0:
                            continue


    if errors > 0:
        print("\n{0} from {1} APIs ended with errors".format(
            errors, len(conf['apis_config']['apis'])))
        exit(1)

if __name__ == "__main__":
    main()
