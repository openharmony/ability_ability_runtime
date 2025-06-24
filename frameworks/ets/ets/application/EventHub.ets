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
    this.context = context;
  }

  on(event: string, callback: Function): void {
    if (!this.eventMap.has(event)) {
      this.eventMap.set(event, []);
    }
    const callbacks = this.eventMap.get(event)!;
    callbacks.push(callback);
    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
  }

  off(event: string, callback: Function): void {
    if (!this.eventMap.has(event)) {
      return;
    }
    const callbacks = this.eventMap.get(event)!;
    const index = callbacks.indexOf(callback);
    if (index > -1) {
      callbacks.splice(index, 1);
    }
    if (callbacks.length === 0) {
      this.eventMap.delete(event); 
    }

    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    this.dynamicContextEventHub!.invokeMethod("off", event, callback);
  }

  offByDynamicContext(event: string, callback: Function): void {
    if (!this.eventMap.has(event)) {
      return;
    }
    const callbacks = this.eventMap.get(event)!;
    const index = callbacks.indexOf(callback);
    if (index > -1) {
      callbacks.splice(index, 1);
    }
    if (callbacks.length === 0) {
      this.eventMap.delete(event); 
    }
  }

  off(event: string): void {
    if (!this.eventMap.has(event)) {
      return;
    }
    this.eventMap.delete(event);

    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    this.dynamicContextEventHub!.invokeMethod("off", event);
  }

  offByDynamicContext(event: string): void {
    if (!this.eventMap.has(event)) {
      return;
    }
    this.eventMap.delete(event);

    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
  }

  private emitWithStaticContext(event: string, ...args: FixedArray<NullishType>): void {
    if (!this.eventMap.has(event)) {
      return;
    }
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
    this.emitWithStaticContext(event, ...args);
    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    this.dynamicContextEventHub!.invokeMethod("emitByNativeContext", event, args);
  }

  emitByDynamicContext(event: string, ...args: FixedArray<NullishType>): void {
    this.emitWithStaticContext(event, ...args);
  }
}