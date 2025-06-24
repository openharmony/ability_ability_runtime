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

export type ESValueArgs = ESValue | Object | null | undefined

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
    console.log(this.eventMap);
  }

  off(event: string, callback: Function): void {
    console.log("off with callback");
    if (!this.eventMap.has(event)) {
      console.log(`Event '${event}' does not exist.`);
      return;
    }
    const callbacks = this.eventMap.get(event)!;
    const index = callbacks.indexOf(callback);
    if (index === -1) {
      console.log(`Callback not found for event '${event}'.`);
    } else {
      callbacks.splice(index, 1);
      console.log(`Callback removed for event '${event}'.`);
    }
    if (callbacks.length === 0) {
      this.eventMap.delete(event);
      console.log(`Event '${event}' has no more callbacks, deleted from eventMap.`);
    }

    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    this.dynamicContextEventHub!.getProperty("eventHub").invokeMethod("offByNativeContext", ESValue.wrap(event), ESValue.wrap(callback));
    console.log(this.eventMap);
  }

  offByDynamicContext(event: string, callback: Function): void {
    console.log("offByDynamicContext with callback");
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
    console.log("off without callback");
    if (!this.eventMap.has(event)) {
      return;
    }
    this.eventMap.delete(event);

    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    console.log("offByDynamicContext 4");
    this.dynamicContextEventHub!.getProperty("eventHub").invokeMethod("offByNativeContext", ESValue.wrap(event));
    console.log(this.eventMap);
  }

  offByDynamicContext(event: string): void {
    console.log("offByDynamicContext without callback");
    if (!this.eventMap.has(event)) {
      return;
    }
    this.eventMap.delete(event);

    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    console.log("offByDynamicContext 4");
    console.log(this.eventMap);
  }

  private emitWithStaticContext(event: string, ...args: FixedArray<(Object|null|undefined)>): void {
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
  
  emit(event: string, ...args: FixedArray<(Object|null|undefined)>): void {
    this.emitWithStaticContext(event, ...args);
    if (!this.dynamicContextEventHub) {
      this.dynamicContextEventHub = this.getDynamicContextEventHub();
    }
    let params: FixedArray<ESValueArgs> = new ESValueArgs[args.length + 1];
    params[0] = ESValue.wrap(event);
    for (let i = 0; i < args.length; i++) {
      params[i + 1] = ESValue.wrap(args[i]);
    }
    this.dynamicContextEventHub!.getProperty("eventHub").invokeMethod("emitByNativeContext", ...params);
  }

  emitByDynamicContext(event: string, ...args: FixedArray<(Object|null|undefined)>): void {
    console.log("emitByDynamicContext 1");
    this.emitWithStaticContext(event, ...args);
  }
}