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
            'enrich_ip_with_virustotal': actions.enrich_observable_with_virustotal,
            'extract_observables': actions.extract_observables,
            'add_firewall_rule': actions.add_firewall_rule,
            'create_incident': actions.create_incident,
            'send_notification': actions.send_notification,
            'isolate_host': actions.isolate_host,
            'lock_user_account': actions.lock_user_account,
            'query_edr_for_processes': actions.query_edr_for_processes,
            'submit_hash_to_sandbox': actions.submit_hash_to_sandbox,
            'generate_firewall_rule': actions.generate_firewall_rule,
        }
        print(f"✅ Playbook engine initialized. Loaded {len(self.playbooks)} playbooks.")

    def _load_playbooks(self):
        
        loaded_playbooks = []
        for filename in os.listdir(self.playbook_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.playbook_dir, filename)
                with open(filepath, 'r') as f:
                    playbook_data = json.load(f)
                    loaded_playbooks.append(playbook_data)
        return loaded_playbooks

    def _resolve_value(self, value, context):
        """
        Bir değeri, listenin veya sözlüğün içinde olsa bile
        kontekste göre özyineli (recursive) olarak çözer.
        """
        
        # 1. Değer bir SÖZLÜK (dict) ise:
        if isinstance(value, dict):
            # İçindeki her bir anahtar/değer çifti için _resolve_params'ı çağır
            return self._resolve_params(value, context)
            
        # 2. Değer bir LİSTE (list) ise:
        if isinstance(value, list):
            # İçindeki her bir öğe için kendini (bu fonksiyonu) tekrar çağır
            resolved_list = []
            for item in value:
                resolved_list.append(self._resolve_value(item, context))
            return resolved_list

        # 3. Değer bir METİN (str) değilse (int, bool, None vb.):
        if not isinstance(value, str):
            # Olduğu gibi döndür
            return value

        # 4. Değer bir METİN (str) ise (Asıl işimiz):
        # Case 4a: Değerin tamamı bir değişkendir, örn: "{{context.1.list}}"
        match = re.fullmatch(r'\{\{([\w\._]+)\}\}', value)
        if match:
            path_keys = match.group(1).split('.')
            temp_data = context
            for p_key in path_keys:
                if isinstance(temp_data, dict):
                    temp_data = temp_data.get(p_key)
                else: return None
            return temp_data

        # Case 4b: Değer bir metnin içinde değişkenler içerir, örn: "IP: {{event.ip}}"
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
        """
        _resolve_value'yu kullanarak bir sözlüğün tamamını çözer.
        """
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
        
