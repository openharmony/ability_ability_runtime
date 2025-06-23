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
import Context from 'application.Context';
import hilog from '@ohos.hilog';

type RegisterEmitFunction = (event: string, ...args: FixedArray<NullishType>) => void;

interface EventHubRegistration {
  registerOn: (event: string, callback: Function) => void;
  registerOff: (event: string, callback?: Function) => void;
  registerEmit: RegisterEmitFunction;
}

export default class EventHub {
  private context?: Context;
  private eventMap: Map<string, Function[]> = new Map<string, Function[]>();
  private dynamicContextEventHub?: ESValue;
  private native getDynamicContextEventHub(): ESValue;

  setContext(context: Context) {
    console.log("set context");
    this.context = context;
  }

  on(event: string, callback: Function): void {
    console.log("1");
    if (!this.eventMap.has(event)) {
      this.eventMap.set(event, []);
    }
    console.log("2");
    const callbacks = this.eventMap.get(event)!;
    callbacks.push(callback);
    console.log("3");
    if (!this.dynamicContextEventHub) {
      console.log("4");
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    console.log("5");
  }

  off(event: string, callback?: Function, fromDynamic: boolean = false): void {
    console.log("off 1");
    if (!this.eventMap.has(event)) {
      return;
    }
    console.log("off 2");
    if (!callback) {
      this.eventMap.delete(event);
    } else {
      const callbacks = this.eventMap.get(event)!;
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
      if (callbacks.length === 0) {
        this.eventMap.delete(event); 
      }
    }
    console.log("off 3");
    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    console.log("off 4");
    if (!fromDynamic) {
      console.log("off 5");
      this.dynamicContextEventHub!.invokeMethod("off", event, callback);
    }
  }

  private emitWithStaticContext(event: string, ...args: FixedArray<NullishType>): void {
    console.log("emitWithStaticContext 1");
    if (!this.eventMap.has(event)) {
      return;
    }
    console.log("emitWithStaticContext 2");
    const callbacks = [...this.eventMap.get(event)!];

    callbacks.forEach(callback => {
      try {
        callback.unsafeCall(...args);
      } catch (err) {
        console.error(`Error '${event}'`, err);
      }
    });
  }
  
  emit(event: string, ...args: FixedArray<NullishType>): void {
    console.log("emit 1");
    this.emitWithStaticContext(event, ...args);
    console.log("emit 2");
    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    console.log("emit 3");
    this.dynamicContextEventHub!.invokeMethod("emitByNativeContext", event, args);
  }

  emitByDynamicContext(event: string, ...args: FixedArray<NullishType>): void {
    console.log("emitByDynamicContext 1");
    this.emitWithStaticContext(event, ...args);
  }
}