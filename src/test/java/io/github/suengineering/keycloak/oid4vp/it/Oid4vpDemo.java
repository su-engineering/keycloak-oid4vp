/* Copyright 2026 su-engineering. SPDX-License-Identifier: Apache-2.0 */
package io.github.suengineering.keycloak.oid4vp.it;

import java.util.Map;
import java.util.concurrent.CountDownLatch;

/** Disposable local demo using generated certificates and synthetic wallet credentials. */
public final class Oid4vpDemo {
    private Oid4vpDemo() {}

    public static void main(String[] args) throws Exception {
        Oid4vpE2eEnvironment env = Oid4vpE2eEnvironment.startDemo();
        Runtime.getRuntime().addShutdownHook(new Thread(env::close));
        String realmPath = "/admin/realms/" + Oid4vpE2eEnvironment.REALM;
        env.adminClient().putJson(realmPath, Map.of("loginTheme", "su-engineering", "displayName", "Wallet demo"));
        String accountUrl = env.keycloakHostUrl() + "/realms/" + Oid4vpE2eEnvironment.REALM + "/account/";
        System.out.println("\nLocal demo ready (synthetic credentials; admin/admin). Keep this terminal open.");
        System.out.println("Sign in: " + accountUrl);
        System.out.println("Admin:   " + env.keycloakHostUrl() + "/admin/");
        System.out.println("Wallet:  " + env.wallet().getBaseUrl());
        System.out.println("Press Ctrl+C to stop and remove the demo containers.\n");
        new CountDownLatch(1).await();
    }
}
