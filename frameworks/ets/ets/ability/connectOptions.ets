/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { ElementName } from 'bundleManager.ElementName'
import rpc from '@ohos.rpc';

export interface ConnectOptions {
    onConnect(elementName: ElementName, remote: rpc.IRemoteObject): void;
    onDisconnect(elementName: ElementName): void;
    onFailed(code: int): void;
}

class ConnectOptionsInner implements ConnectOptions {
    onConnect(elementName: ElementName, remote: rpc.IRemoteObject): void {
        console.log('onConnect');
    }
    onDisconnect(elementName: ElementName): void {
        console.log('onDisconnect');
    }
    onFailed(code: int): void {
        console.log('onFailed');
    }
}
