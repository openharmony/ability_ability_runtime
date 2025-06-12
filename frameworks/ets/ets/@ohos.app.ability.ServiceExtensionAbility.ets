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

class MyService extends rpc.RemoteObject {
  constructor(descriptor: string) {
    super(descriptor);
  }

  public onRemoteMessageRequest(
    code: number,
    data: rpc.MessageSequence,
    reply: rpc.MessageSequence,
    options: rpc.MessageOption
  ): boolean | Promise<boolean> {
    return false;
  }
}

export default class ServiceExtensionAbility {
  private connectCallbackPoint: long;

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

  private isOnDisconnectAsync: boolean = true;
  private disconnectCallbackPoint: long;

  private native nativeOnDisconnectCallback(): void;

  private callOnDisconnect(want: Want): void {
    let p = this.onDisconnectAsync(want);
    if (this.isOnDisconnectAsync) {
      p.then<void>((a: undefined): void => {
        this.nativeOnDisconnectCallback();
      });
    } else {
      this.onDisconnect(want);
    }
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
    console.log("onDisconnectAsync");
    this.isOnDisconnectAsync = false;
    return new Promise<void>((resolve: (a: undefined) => void, reject: (err: Error) => void): void => {
    });
  }
}