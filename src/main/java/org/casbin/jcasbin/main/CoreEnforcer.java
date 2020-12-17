// Copyright 2017 The casbin Authors. All Rights Reserved.
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

package org.casbin.jcasbin.main;

import com.googlecode.aviator.AviatorEvaluator;
import com.googlecode.aviator.AviatorEvaluatorInstance;
import com.googlecode.aviator.Expression;
import com.googlecode.aviator.runtime.type.AviatorFunction;
import org.casbin.jcasbin.effect.DefaultEffector;
import org.casbin.jcasbin.effect.Effect;
import org.casbin.jcasbin.effect.Effector;
import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.exception.CasbinMatcherException;
import org.casbin.jcasbin.model.Assertion;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Watcher;
import org.casbin.jcasbin.persist.WatcherEx;
import org.casbin.jcasbin.persist.file_adapter.FilteredAdapter;
import org.casbin.jcasbin.rbac.DefaultRoleManager;
import org.casbin.jcasbin.rbac.RoleManager;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.Util;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
public class CoreEnforcer {
    String modelPath;
    Model model;
    FunctionMap fm;
    private Effector eft;

    Adapter adapter;
    Watcher watcher;
    RoleManager rm;

    private boolean enabled;
    boolean autoSave;
    boolean autoBuildRoleLinks;
    boolean autoNotifyWatcher = true;

    // cached instance of AviatorEvaluatorInstance
    AviatorEvaluatorInstance aviatorEval;

    // detect changes in Model so that we can invalidate AviatorEvaluatorInstance cache
    int modelModCount;

    void initialize() {
        rm = new DefaultRoleManager(10);
        eft = new DefaultEffector();
        watcher = null;

        enabled = true;
        autoSave = true;
        autoBuildRoleLinks = true;
    }

    /**
     * newModel creates a model.
     *
     * @return an empty model.
     */
    public static Model newModel(RedisTemplate<String, Map<String, Assertion>> redisTemplate, String tenantry) {
        return new Model(redisTemplate, tenantry);
    }

    /**
     * newModel creates a model.
     *
     * @param text the model text.
     * @return the model.
     */
    public static Model newModel(String text, RedisTemplate<String, Map<String, Assertion>> redisTemplate, String tenantry) {
        Model m = new Model(redisTemplate, tenantry);
        m.loadModelFromText(text);
        return m;
    }

    /**
     * newModel creates a model.
     *
     * @param modelPath the path of the model file.
     * @param unused    unused parameter, just for differentiating with
     *                  newModel(String text).
     * @return the model.
     */
    public static Model newModel(String modelPath, String unused, RedisTemplate<String, Map<String, Assertion>> redisTemplate, String tenantry) {
        Model m = new Model(redisTemplate, tenantry);

        if (!"".equals(modelPath)) {
            m.loadModel(modelPath);
        }

        return m;
    }


    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model, so the policy is invalidated
     * and needs to be reloaded by calling LoadPolicy().
     */
    public void loadModel(RedisTemplate<String, Map<String, Assertion>> redisTemplate, String tenantry) {
        model = newModel(redisTemplate, tenantry);
        model.loadModel(this.modelPath);
        model.printModel();
        fm = FunctionMap.loadFunctionMap();
        aviatorEval = null;
    }

    /**
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
     */
    public Model getModel() {
        return model;
    }

    /**
     * setModel sets the current model.
     *
     * @param model the model.
     */
    public void setModel(Model model) {
        this.model = model;
        fm = FunctionMap.loadFunctionMap();
        aviatorEval = null;
    }

    /**
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
     */
    public Adapter getAdapter() {
        return adapter;
    }

    /**
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
     */
    public void setAdapter(Adapter adapter) {
        this.adapter = adapter;
    }

    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    public void setWatcher(Watcher watcher) {
        this.watcher = watcher;
        watcher.setUpdateCallback(this::loadPolicy);
    }

    /**
     * SetRoleManager sets the current role manager.
     *
     * @param rm the role manager.
     */
    public void setRoleManager(RoleManager rm) {
        this.rm = rm;
    }

    /**
     * setEffector sets the current effector.
     *
     * @param eft the effector.
     */
    public void setEffector(Effector eft) {
        this.eft = eft;
    }

    /**
     * clearPolicy clears all policy.
     */
    public void clearPolicy() {
        model.clearPolicy();
    }

    /**
     * loadPolicy reloads the policy from file/database.
     */
    public void loadPolicy() {
        model.clearPolicy();
        // model.initPolicy();
        adapter.loadPolicy(model);

        model.printPolicy();
        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
        // 初始化数据到redis
        model.model.forEach((sec, value) -> value.forEach((ptype, asc) -> model.getRedisKey(sec).put(ptype, asc)));
        model.model = null;
    }

    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    public void loadFilteredPolicy(Object filter) {
        model.clearPolicy();
        // model.initPolicy();
        FilteredAdapter filteredAdapter;
        if (adapter instanceof FilteredAdapter) {
            filteredAdapter = (FilteredAdapter) adapter;
        } else {
            throw new CasbinAdapterException("Filtered policies are not supported by this adapter.");
        }
        try {
            filteredAdapter.loadFilteredPolicy(model, filter);
        } catch (Exception e) {
            e.printStackTrace();
        }
        model.printPolicy();
        if (autoBuildRoleLinks) {
            buildRoleLinks();
        }
        // 初始化数据到redis
        model.model.forEach((sec, value) -> value.forEach((ptype, asc) -> model.getRedisKey(sec).put(ptype, asc)));
        model.model = null;
    }

    /**
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
     */
    public boolean isFiltered() {
        if (adapter instanceof FilteredAdapter) {
            return ((FilteredAdapter) adapter).isFiltered();
        }
        return false;
    }

    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    public void savePolicy() {
        if (isFiltered()) {
            throw new IllegalArgumentException("cannot save a filtered policy");
        }

        adapter.savePolicy(model);
        if (watcher != null && autoNotifyWatcher) {
            if (watcher instanceof WatcherEx) {
                ((WatcherEx) watcher).updateForSavePolicy(model);
            } else {
                watcher.update();
            }
        }
    }

    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
     */
    public void enableEnforce(boolean enable) {
        this.enabled = enable;
    }

    /**
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
     */
    public void enableLog(boolean enable) {
        Util.enableLog = enable;
    }

    /**
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
     */
    public void enableAutoSave(boolean autoSave) {
        this.autoSave = autoSave;
    }

    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
     */
    public void enableAutoBuildRoleLinks(boolean autoBuildRoleLinks) {
        this.autoBuildRoleLinks = autoBuildRoleLinks;
    }

    /**
     * buildRoleLinks manually rebuild the
     * role inheritance relations.
     */
    public void buildRoleLinks() {
        rm.clear();
        model.buildRoleLinks(rm);
    }

    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    public boolean enforce(Object... rvals) {
        if (!enabled) {
            return true;
        }
        if (aviatorEval == null || modelModCount != model.getModCount()) {
            synchronized (this) {
                if (aviatorEval == null || modelModCount != model.getModCount()) {
                    // AviatorEvaluator instance must be rebuild
                    Map<String, AviatorFunction> functions = new HashMap<>();
                    for (Map.Entry<String, AviatorFunction> entry : fm.fm.entrySet()) {
                        String key = entry.getKey();
                        AviatorFunction function = entry.getValue();

                        functions.put(key, function);
                    }
                    Map<String, Assertion> entries = model.getRedisKey("g").entries();
                    if (entries != null) {
                        for (Map.Entry<String, Assertion> entry : entries.entrySet()) {
                            String key = entry.getKey();
                            Assertion ast = entry.getValue();

                            RoleManager rm = ast.rm;
                            functions.put(key, BuiltInFunctions.generateGFunction(key, rm));
                        }
                    }

                    aviatorEval = AviatorEvaluator.newInstance();
                    for (AviatorFunction f : functions.values()) {
                        aviatorEval.addFunction(f);
                    }
                    modelModCount = model.getModCount();
                }
            }
        }
        String expString = model.getRedisKey("m").get("m").value;
        Expression expression = aviatorEval.compile(expString, true);

        Effect policyEffects[];
        float matcherResults[];
        int policyLen;
        Assertion astp = model.getRedisKey("p").get("p");
        Assertion aste = model.getRedisKey("e").get("e");
        if ((policyLen = astp.policy.size()) != 0) {
            policyEffects = new Effect[policyLen];
            matcherResults = new float[policyLen];

            for (int i = 0; i < astp.policy.size(); i++) {
                List<String> pvals = astp.policy.get(i);

                // Select the rule based on request size
                Map<String, Object> parameters = new HashMap<>();
                getRTokens(parameters, rvals);
                for (int j = 0; j < astp.tokens.length; j++) {
                    String token = astp.tokens[j];
                    parameters.put(token, pvals.get(j));
                }

                Object result = expression.execute(parameters);
                // Util.logPrint("Result: " + result);

                if (result instanceof Boolean) {
                    if (!((boolean) result)) {
                        policyEffects[i] = Effect.Indeterminate;
                        continue;
                    }
                } else if (result instanceof Float) {
                    if ((float) result == 0) {
                        policyEffects[i] = Effect.Indeterminate;
                        continue;
                    } else {
                        matcherResults[i] = (float) result;
                    }
                } else {
                    throw new CasbinMatcherException("matcher result should be bool, int or float");
                }
                if (parameters.containsKey("p_eft")) {
                    String eft = (String) parameters.get("p_eft");
                    if ("allow".equals(eft)) {
                        policyEffects[i] = Effect.Allow;
                    } else if ("deny".equals(eft)) {
                        policyEffects[i] = Effect.Deny;
                    } else {
                        policyEffects[i] = Effect.Indeterminate;
                    }
                } else {
                    policyEffects[i] = Effect.Allow;
                }

                if ("priority(p_eft) || deny".equals(aste.value)) {
                    break;
                }
            }
        } else {
            policyEffects = new Effect[1];
            matcherResults = new float[1];

            Map<String, Object> parameters = new HashMap<>();
            Assertion astr = model.getRedisKey("r").get("r");
            for (int j = 0; j < astr.tokens.length; j++) {
                String token = astr.tokens[j];
                parameters.put(token, rvals[j]);
            }
            for (int j = 0; j < astp.tokens.length; j++) {
                String token = astp.tokens[j];
                parameters.put(token, "");
            }

            Object result = expression.execute(parameters);
            // Util.logPrint("Result: " + result);

            if ((boolean) result) {
                policyEffects[0] = Effect.Allow;
            } else {
                policyEffects[0] = Effect.Indeterminate;
            }
        }

        boolean result = eft.mergeEffects(aste.value, policyEffects, matcherResults);

        StringBuilder reqStr = new StringBuilder("Request: ");
        for (int i = 0; i < rvals.length; i++) {
            String rval = rvals[i].toString();

            if (i != rvals.length - 1) {
                reqStr.append(String.format("%s, ", rval));
            } else {
                reqStr.append(String.format("%s", rval));
            }
        }
        reqStr.append(String.format(" ---> %s", result));
        Util.logPrint(reqStr.toString());

        return result;
    }

    private void getRTokens(Map<String, Object> parameters, Object... rvals) {
        BoundHashOperations<String, String, Assertion> astr = model.getRedisKey("r");
        if (astr == null) {
            return;
        }
        for (String rKey : astr.entries().keySet()) {
            String[] tokens = astr.get(rKey).tokens;
            if (rvals.length != tokens.length) {
                continue;
            }
            for (int j = 0; j < tokens.length; j++) {
                String token = tokens[j];
                parameters.put(token, rvals[j]);
            }

        }
    }

    public boolean validateEnforce(Object... rvals) {
        return validateEnforceSection("r", rvals);
    }

    private boolean validateEnforceSection(String section, Object... rvals) {
        Map<String, Assertion> assertionMap = getModel().getRedisKey(section).entries();
        if (assertionMap == null) {
            throw new CasbinMatcherException("Could not find " + section + " definition in model");
        }
        Assertion ast = assertionMap.get(section);
        if (ast == null) {
            throw new CasbinMatcherException("Could not find " + section + " definition in model");
        }
        int expectedParamSize = ast.tokens.length;

        if (rvals.length != expectedParamSize) {
            Util.logPrintfWarn("Incorrect number of attributes to check for policy (expected {} but got {})",
                expectedParamSize, rvals.length);
            return rvals.length >= expectedParamSize;
        }
        return true;
    }

    /**
     * Invalidate cache of compiled model matcher expression. This is done automatically most of the time, but you may
     * need to call it explicitly if you manipulate directly Model.
     */
    public void resetExpressionEvaluator() {
        aviatorEval = null;
    }

    public boolean isAutoNotifyWatcher() {
        return autoNotifyWatcher;
    }

    public void setAutoNotifyWatcher(boolean autoNotifyWatcher) {
        this.autoNotifyWatcher = autoNotifyWatcher;
    }
}
