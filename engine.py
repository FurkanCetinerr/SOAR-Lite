# engine.py

import os
import json
import re
import actions

class PlaybookEngine:
    def __init__(self, playbook_dir='playbooks'):
        self.playbook_dir = playbook_dir
        self.playbooks = self._load_playbooks()
        self.action_dispatcher = {
            'enrich_ip_with_virustotal': actions.enrich_ip_with_virustotal,
            'extract_and_enrich_observables': actions.extract_and_enrich_observables,
            'add_firewall_rule': actions.add_firewall_rule,
            'create_incident': actions.create_incident,
            'send_notification': actions.send_notification,
            'isolate_host': actions.isolate_host,
            'lock_user_account': actions.lock_user_account,
            'query_edr_for_processes': actions.query_edr_for_processes,
            'submit_hash_to_sandbox': actions.submit_hash_to_sandbox,
        }
        print(f"✅ Playbook engine initialized. Loaded {len(self.playbooks)} playbooks.")

    def _load_playbooks(self):
        # ... (Değişiklik yok)
        loaded_playbooks = []
        for filename in os.listdir(self.playbook_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.playbook_dir, filename)
                with open(filepath, 'r') as f:
                    playbook_data = json.load(f)
                    loaded_playbooks.append(playbook_data)
        return loaded_playbooks

    def _resolve_value(self, value, context):
        if not isinstance(value, str):
            return value

        # Case 1: The entire value is a placeholder. Replace it while preserving its type.
        match = re.fullmatch(r'\{\{([\w\._]+)\}\}', value)
        if match:
            path_keys = match.group(1).split('.')
            temp_data = context
            for p_key in path_keys:
                if isinstance(temp_data, dict):
                    temp_data = temp_data.get(p_key)
                else: return None
            return temp_data

        # Case 2: The value contains placeholders within a string.
        def replace_match(m):
            path_keys = m.group(1).split('.')
            temp_data = context
            for p_key in path_keys:
                if isinstance(temp_data, dict):
                    temp_data = temp_data.get(p_key)
                else: return m.group(0)
            return str(temp_data) if temp_data is not None else m.group(0)

        return re.sub(r'\{\{([\w\._]+)\}\}', replace_match, value)
    
    def _resolve_params(self, params, context):
        resolved_params = {}
        for key, value in params.items():
            resolved_params[key] = self._resolve_value(value, context)
        return resolved_params
    
    def run(self, event):
        event_type = event.get('event_type')
        if not event_type: return

        print(f"\n▶️  Processing event: {event_type}")

        for playbook in self.playbooks:
            if playbook['trigger']['event_type'] == event_type:
                print(f"📖 Matching playbook found: '{playbook['name']}'")
                
                context = {'event': event}
                mitre_mapping = playbook.get('mitre_mapping', {})
                
                for step in playbook['steps']:
                    condition_str = step.get('condition')
                    if condition_str:
                        resolved_condition = self._resolve_value(condition_str, context)
                        try:
                            condition_result = eval(resolved_condition, {"__builtins__": {}}, {})
                        except:
                            condition_result = False
                        
                        if not condition_result:
                            print(f"  -> Skipping step due to unmet condition: '{condition_str}'")
                            continue
                    
                    action_type = step['action_type']
                    params = self._resolve_params(step.get('params', {}), context)
                    params['event_type'] = event_type
                    params['mitre_mapping'] = mitre_mapping
                    
                    action_function = self.action_dispatcher.get(action_type)
                    if action_function:
                        print(f"  Executing action: '{action_type}'")
                        result = action_function(params)
                        if isinstance(result, dict):
                            context.update(result)
                    else:
                        print(f"  -> ⚠️  Unknown action type: '{action_type}'. Skipping.")
                return

        print(f"⚠️ No playbook found for event_type: '{event_type}'")
        
