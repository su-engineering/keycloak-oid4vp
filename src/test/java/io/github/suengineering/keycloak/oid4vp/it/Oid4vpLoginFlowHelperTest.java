/*
 * Copyright 2026 su-engineering
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.suengineering.keycloak.oid4vp.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import org.junit.jupiter.api.Test;

class Oid4vpLoginFlowHelperTest {

    private static final String WALLET_URL = "openid4vp://authorize?request_uri=https://example.com/request";
    private static final String DENIAL_BODY = "{\"error\":\"access_denied\"}";

    private final Oid4vcContainer wallet = mock(Oid4vcContainer.class);
    private final Runnable configureDenial = mock(Runnable.class);
    private final Oid4vpLoginFlowHelper flow = new Oid4vpLoginFlowHelper(null, null, wallet, null, null, null);

    @Test
    void reconfiguresOneShotWalletErrorBeforeRetryingExpiredSession() {
        PresentationResponse expiredSession = mock(PresentationResponse.class);
        when(expiredSession.rawBody()).thenReturn("""
                        {"response":{"status_code":400,"body":"{\\"error\\":\\"session_expired\\"}"}}
                        """);
        PresentationResponse denial = denial();
        when(wallet.acceptPresentationRequest(WALLET_URL)).thenReturn(expiredSession, denial);

        var response = flow.submitToWallet(WALLET_URL, configureDenial);

        assertThat(response.rawBody()).isEqualTo(DENIAL_BODY);
        var order = inOrder(configureDenial, wallet);
        order.verify(configureDenial).run();
        order.verify(wallet).acceptPresentationRequest(WALLET_URL);
        order.verify(configureDenial).run();
        order.verify(wallet).acceptPresentationRequest(WALLET_URL);
        order.verifyNoMoreInteractions();
    }

    @Test
    void doesNotRetryWalletDenial() {
        PresentationResponse denial = denial();
        when(wallet.acceptPresentationRequest(WALLET_URL)).thenReturn(denial);

        var response = flow.submitToWallet(WALLET_URL, configureDenial);

        assertThat(response.rawBody()).isEqualTo(DENIAL_BODY);
        var order = inOrder(configureDenial, wallet);
        order.verify(configureDenial).run();
        order.verify(wallet).acceptPresentationRequest(WALLET_URL);
        order.verifyNoMoreInteractions();
    }

    private PresentationResponse denial() {
        PresentationResponse response = mock(PresentationResponse.class);
        when(response.rawBody()).thenReturn(DENIAL_BODY);
        return response;
    }
}
