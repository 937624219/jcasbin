// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.jcasbin.model;

import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.Util;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Policy {
    private static final String CASBIN_REDIS_KEY = "JCASBIN_REDIS_KEY::";
    private final RedisTemplate<String, Map<String, Assertion>> redisTemplate;

    public Policy(RedisTemplate<String, Map<String, Assertion>> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * buildRoleLinks initializes the roles in RBAC.
     *
     * @param rm the role manager.
     */
    public void buildRoleLinks(RoleManager rm) {
        Map<String, Assertion> entriesG = this.getRedisKey("g").entries();
        if (entriesG != null && !entriesG.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesG.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                ast.buildRoleLinks(rm);
                this.getRedisKey("g").put(key, ast);
            }
        }
    }

    /**
     * printPolicy prints the policy to log.
     */
    public void printPolicy() {
        Util.logPrint("Policy:");
        Map<String, Assertion> entriesP = this.getRedisKey("p").entries();
        if (entriesP != null && !entriesP.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesP.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
            }
        }

        Map<String, Assertion> entriesG = this.getRedisKey("g").entries();
        if (entriesG != null && !entriesG.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesG.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                Util.logPrint(key + ": " + ast.value + ": " + ast.policy);
            }
        }
    }

    /**
     * savePolicyToText saves the policy to the text.
     *
     * @return the policy text.
     */
    public String savePolicyToText() {
        StringBuilder res = new StringBuilder();

        Map<String, Assertion> entriesP = this.getRedisKey("p").entries();
        if (entriesP != null && !entriesP.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesP.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                for (List<String> rule : ast.policy) {
                    res.append(key).append(", ").append(String.join(", ", rule)).append("\n");
                }
            }
        }

        Map<String, Assertion> entriesG = this.getRedisKey("g").entries();
        if (entriesG != null && !entriesG.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesG.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                for (List<String> rule : ast.policy) {
                    res.append(key).append(", ").append(String.join(", ", rule)).append("\n");
                }
            }
        }

        return res.toString();
    }

    /**
     * clearPolicy clears all current policy.
     */
    public void clearPolicy() {
        Map<String, Assertion> entriesP = this.getRedisKey("p").entries();
        if (entriesP != null && !entriesP.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesP.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                ast.policy = new ArrayList<>();
                this.getRedisKey("p").put(key, ast);
            }
        }

        Map<String, Assertion> entriesG = this.getRedisKey("g").entries();
        if (entriesG != null && !entriesG.isEmpty()) {
            for (Map.Entry<String, Assertion> entry : entriesG.entrySet()) {
                String key = entry.getKey();
                Assertion ast = entry.getValue();
                ast.policy = new ArrayList<>();
                this.getRedisKey("g").put(key, ast);
            }
        }
    }


    /**
     * getPolicy gets all rules in a policy.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @return the policy rules of section sec and policy type ptype.
     */
    public List<List<String>> getPolicy(String sec, String ptype) {
        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return new ArrayList<>();
        }
        return ast.policy;
    }

    /**
     * getFilteredPolicy gets rules based on field filters from a policy.
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered policy rules of section sec and policy type ptype.
     */
    public List<List<String>> getFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> res = new ArrayList<>();

        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return new ArrayList<>();
        }
        for (List<String> rule : ast.policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i++) {
                String fieldValue = fieldValues[i];
                if (!"".equals(fieldValue) && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                res.add(rule);
            }
        }
        return res;
    }

    /**
     * hasPolicy determines whether a model has the specified policy rule.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule  the policy rule.
     * @return whether the rule exists.
     */
    public boolean hasPolicy(String sec, String ptype, List<String> rule) {
        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return false;
        }
        for (List<String> r : ast.policy) {
            if (Util.arrayEquals(rule, r)) {
                return true;
            }
        }
        return false;
    }

    /**
     * addPolicy adds a policy rule to the model.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule  the policy rule.
     * @return succeeds or not.
     */
    public boolean addPolicy(String sec, String ptype, List<String> rule) {
        if (!hasPolicy(sec, ptype, rule)) {
            Assertion ast = this.getRedisKey(sec).get(ptype);
            if (ast == null) {
                return false;
            }
            ast.policy.add(rule);
            this.getRedisKey(sec).put(ptype, ast);
            return true;
        }
        return false;
    }

    /**
     * addPolicies adds policy rules to the model.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
     */
    public boolean addPolicies(String sec, String ptype, List<List<String>> rules) {
        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return false;
        }
        int size = ast.policy.size();
        for (List<String> rule : rules) {
            if (!hasPolicy(sec, ptype, rule)) {
                ast.policy.add(rule);
            }
        }
        boolean ok = size < ast.policy.size();
        if (ok) {
            this.getRedisKey(sec).put(ptype, ast);
        }
        return ok;
    }

    /**
     * removePolicy removes a policy rule from the model.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rule  the policy rule.
     * @return succeeds or not.
     */
    public boolean removePolicy(String sec, String ptype, List<String> rule) {
        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return false;
        }
        List<List<String>> policy = ast.policy;
        for (int i = policy.size() - 1; i >= 0; i--) {
            List<String> r = policy.get(i);
            if (Util.arrayEquals(rule, r)) {
                policy.remove(i);
                this.getRedisKey(sec).put(ptype, ast);
                return true;
            }
        }
        return false;
    }

    /**
     * removePolicies removes rules from the current policy.
     *
     * @param sec   the section, "p" or "g".
     * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
     * @param rules the policy rules.
     * @return succeeds or not.
     */
    public boolean removePolicies(String sec, String ptype, List<List<String>> rules) {
        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return false;
        }
        List<List<String>> policy = ast.policy;
        int size = policy.size();
        for (List<String> rule : rules) {
            for (int i = policy.size() - 1; i >= 0; i--) {
                List<String> r = policy.get(i);
                if (Util.arrayEquals(rule, r)) {
                    policy.remove(i);
                }
            }
        }
        boolean ok = size > policy.size();
        if (ok) {
            this.getRedisKey(sec).put(ptype, ast);
        }
        return ok;
    }

    /**
     * removeFilteredPolicyReturnsEffects removes policy rules based on field filters from the model.
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds(effects.size () &gt; 0) or not.
     */
    public List<List<String>> removeFilteredPolicyReturnsEffects(String sec, String ptype, int fieldIndex, String... fieldValues) {
        List<List<String>> tmp = new ArrayList<>();
        List<List<String>> effects = new ArrayList<>();
        int firstIndex = -1;

        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return effects;
        }
        for (List<String> rule : ast.policy) {
            boolean matched = true;
            for (int i = 0; i < fieldValues.length; i++) {
                String fieldValue = fieldValues[i];
                if (!"".equals(fieldValue) && !rule.get(fieldIndex + i).equals(fieldValue)) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                if (firstIndex == -1) {
                    firstIndex = ast.policy.indexOf(rule);
                }
                effects.add(rule);
            } else {
                tmp.add(rule);
            }
        }

        if (firstIndex != -1) {
            ast.policy = tmp;
            this.getRedisKey(sec).put(ptype, ast);
        }
        return effects;
    }

    /**
     * removeFilteredPolicy removes policy rules based on field filters from the model.
     *
     * @param sec         the section, "p" or "g".
     * @param ptype       the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex  the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    public boolean removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        return !removeFilteredPolicyReturnsEffects(sec, ptype, fieldIndex, fieldValues).isEmpty();
    }

    /**
     * getValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param sec        the section, "p" or "g".
     * @param ptype      the policy type, "p", "p2", .. or "g", "g2", ..
     * @param fieldIndex the policy rule's index.
     * @return the field values specified by fieldIndex.
     */
    public List<String> getValuesForFieldInPolicy(String sec, String ptype, int fieldIndex) {
        List<String> values = new ArrayList<>();

        Assertion ast = this.getRedisKey(sec).get(ptype);
        if (ast == null) {
            return values;
        }
        for (List<String> rule : ast.policy) {
            values.add(rule.get(fieldIndex));
        }

        Util.arrayRemoveDuplicates(values);

        return values;
    }

    public void buildIncrementalRoleLinks(RoleManager rm, Model.PolicyOperations op, String sec, String ptype, List<List<String>> rules) {
        if ("g".equals(sec)) {
            Assertion ast = this.getRedisKey(sec).get(ptype);
            if (ast == null) {
                return;
            }
            ast.buildIncrementalRoleLinks(rm, op, rules);
            this.getRedisKey(sec).put(ptype, ast);
        }
    }

    public boolean hasPolicies(String sec, String ptype, List<List<String>> rules) {
        for (List<String> rule : rules) {
            if (this.hasPolicy(sec, ptype, rule)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取Redis绑定的key
     *
     * @param sec the section, "p" or "g".
     * @return Map<String, Assertion>
     */
    public BoundHashOperations<String, String, Assertion> getRedisKey(String sec) {
        return redisTemplate.boundHashOps(CASBIN_REDIS_KEY + sec);
    }

    /**
     * 获取Redis绑定的所有key , "p" or "g".
     *
     * @return List<String>
     */
    public List<String> getAllKeys() {
        Set<String> keys = redisTemplate.keys(CASBIN_REDIS_KEY + "*");
        if (keys == null) {
            return new ArrayList<>();
        }
        ArrayList<String> list = new ArrayList<>();
        for (String key : keys) {
            key = key.replace(CASBIN_REDIS_KEY, "");
            list.add(key);
        }
        return list;
    }
}
