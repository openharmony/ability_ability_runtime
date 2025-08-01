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

import rpc from '@ohos.rpc';
import Want from '@ohos.app.ability.Want';
import ServiceExtensionContext from 'application.ServiceExtensionContext';
import { Configuration } from '@ohos.app.ability.Configuration'
import hilog from '@ohos.hilog';
import { AbilityUtils } from './utils/AbilityUtils';

class MyService extends rpc.RemoteObject {
  constructor(descriptor: string) {
    super(descriptor);
  }
}

export default class ServiceExtensionAbility {
  private connectCallback: long;

  private native nativeOnConnectCallback(service: rpc.RemoteObject): boolean;

  private checkPromise(obj: NullishType): boolean {
    if (obj instanceof Promise) {
      return true;
    }
    return false;
  }

  private callPromise(p: Promise<rpc.RemoteObject>): boolean {
    let remoteObj: rpc.RemoteObject = await p;
    return this.nativeOnConnectCallback(remoteObj);
  }

  private disconnectCallback: long;

  private native nativeOnDisconnectCallback(): void;

  private callOnDisconnect(want: Want): boolean {
    const derivedClassType = AbilityUtils.getClassType(this);
    if (derivedClassType === undefined) {
      this.onDisconnect(want);
      return false;
    }
    const serviceExtensionClassType = AbilityUtils.getClassType(new ServiceExtensionAbility());
    if (serviceExtensionClassType === undefined) {
      this.onDisconnect(want);
      return false;
    }
    const isOverride = AbilityUtils.isOverride(derivedClassType, "onDisconnectAsync", serviceExtensionClassType);
    if (isOverride) {
      this.onDisconnectAsync(want).then(() => this.nativeOnDisconnectCallback());
      return true;
    }
    this.onDisconnect(want);
    return false;
  }

  launchWant: Want = new Want();
  lastRequestWant: Want = new Want();
  context: ServiceExtensionContext = {};

  onCreate(want: Want): void {
  }

  onDestroy(): void {
  }

  onRequest(want: Want, startld: double): void {
  }

  onConnect(want: Want): rpc.RemoteObject | Promise<rpc.RemoteObject> {
    let myService: rpc.RemoteObject = new MyService("onConnect");
    return myService;
  }

  onDisconnect(want: Want): void {
  }

  onDisconnectAsync(want: Want): Promise<void> {
    return new Promise<void>((resolve: (a: undefined) => void, reject: (err: Error) => void): void => {});
  }

  onConfigurationUpdate(newConfig: Configuration): void {
  }

  onDump(params: Array<string>): Array<string> {
    console.log("onDump");
    return ['params'];
  }
}