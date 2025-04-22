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
  private isOnConnectAsync: boolean = true;
  private connectCallbackPoint: long;
  private native nativeOnConnectCallback(service: rpc.RemoteObject): void;
  private callOnConnect(want: Want): rpc.RemoteObject {
    let p = this.onConnectAsync(want);
    if (this.isOnConnectAsync) {
      p.then((a:rpc.RemoteObject) => {
        this.nativeOnConnectCallback(a);
      });
      return new MyService("onConnectAsync")
    } else {
      return this.onConnect(want);
    }
  }

  private isOnDisconnectAsync: boolean = true;
  private disconnectCallbackPoint: long;
  private native nativeOnDisconnectCallback(): void;
  private callOnDisconnect(want: Want): void {
    let p = this.onDisconnectAsync(want);
    if (this.isOnDisconnectAsync) {
        p.then<void>((a:undefined): void => {
        this.nativeOnDisconnectCallback();
      });
    } else {
      this.onDisconnect(want);
    }
  }
  launchWant: Want = new Want();
  lastRequestWant: Want = new Want();
  context: ServiceExtensionContext = {};
  onCreate(want: Want): void{
    console.log("onCreate");
  }
  onDestroy(): void {
    console.log("ServiceExtensionAbility onRequest");
  }
  onRequest(want: Want, startld: double): void {
    console.log("onRequest");
  }
  onConnect(want: Want): rpc.RemoteObject {
    console.log("onConnect");
    let myService: rpc.RemoteObject = new MyService("onConnect");
    return myService;
  }
  onConnectAsync(want: Want): Promise<rpc.RemoteObject> {
    console.log("onConnectAsync");
    this.isOnConnectAsync = false;
    return new Promise<rpc.RemoteObject>((resolve, reject) => {  
      resolve(new MyService("onConnectAsync")); 
    });  
  }
  onDisconnect(want: Want): void {
    console.log("onDisconnect");
  }
  onDisconnectAsync(want: Want): Promise<void> {
    console.log("onDisconnectAsync");
    this.isOnDisconnectAsync = false;
    return new Promise<void>((resolve: (a: undefined)=>void, reject: (err: Error)=>void): void => {});
  }
}