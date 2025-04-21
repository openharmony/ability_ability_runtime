/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { BusinessError, AsyncCallback } from '@ohos.base';
import Want from '@ohos.app.ability.Want';
import { WantAgentInfo as _WantAgentInfo } from 'wantAgent.wantAgentInfo';
import { TriggerInfo as _TriggerInfo } from 'wantAgent.triggerInfo';
import AsyncCallbackWrapper from './utils/AbilityUtils';

namespace wantAgent {
  loadLibrary("aniwantagent.z");

  native function nativeGetBundleName(agent: WantAgent, callback: AsyncCallbackWrapper<string>): void;
  native function nativeGetUid(agent: WantAgent, callback: AsyncCallbackWrapper<number>): void;
  native function nativeGetOperationType(agent: WantAgent, callback: AsyncCallbackWrapper<number>): void;
  native function nativeCancel(agent: WantAgent, callback: AsyncCallbackWrapper<void>): void;
  native function nativeEqual(agent: WantAgent, otherAgent: WantAgent, callback: AsyncCallbackWrapper<boolean>): void;
  native function nativeTrigger(agent: WantAgent, triggerInfo: TriggerInfo, callback?: AsyncCallbackWrapper<CompleteData>): void;
  native function nativeGetWant(agent: WantAgent, callback: AsyncCallbackWrapper<Want>): void;
  native function nativeGetWantAgent(agent: WantAgentInfo, callback: AsyncCallbackWrapper<WantAgent>): void;
  export function getBundleName(agent: WantAgent, callback: AsyncCallback<string>): void {
    let myCall = new AsyncCallbackWrapper<string>(callback);
    taskpool.execute((): void =>{
      nativeGetBundleName(agent, myCall);
    });
  }
  export function getBundleName(agent: WantAgent): Promise<string> {
    return new Promise<string>((resolve: (data:string)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<string>((err: BusinessError<void>, data: string)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
        nativeGetBundleName(agent, myCall);
      });
    });
  }
  export function getUid(agent: WantAgent, callback: AsyncCallback<number>): void {
    let myCall = new AsyncCallbackWrapper<number>(callback);
    taskpool.execute((): void =>{
      nativeGetUid(agent, myCall);
    });
  }
  export function getUid(agent: WantAgent): Promise<number> {
    return new Promise<number>((resolve: (data:number)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<number>((err: BusinessError<void>, data: number)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
        nativeGetUid(agent, myCall);
    });
    });
  }
  export function getWant(agent: WantAgent, callback: AsyncCallback<Want>): void {
    let myCall = new AsyncCallbackWrapper<Want>(callback);
    taskpool.execute((): void =>{
      nativeGetWant(agent, myCall);
    });
  }
  export function getWant(agent: WantAgent): Promise<Want> {
    return new Promise<Want>((resolve: (data:Want)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Want>((err: BusinessError<void>, data: Want)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
        nativeGetWant(agent, myCall);
    });
    });
  }
  export function cancel(agent: WantAgent, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void =>{
      nativeCancel(agent, myCall);
    });
  }
  export function cancel(agent: WantAgent): Promise<void> {
    return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
        nativeCancel(agent, myCall);
      });
    });
  }
  export function trigger(agent: WantAgent, triggerInfo: TriggerInfo, callback?: AsyncCallback<CompleteData>): void {
    taskpool.execute((): void =>{
      if (callback == undefined) {
        nativeTrigger(agent, triggerInfo);
      } else {
        let myCall = new AsyncCallbackWrapper<CompleteData>(callback);
        nativeTrigger(agent, triggerInfo, myCall);
      }
    });
  }
  export function equal(agent: WantAgent, otherAgent: WantAgent, callback: AsyncCallback<boolean>): void {
    let myCall = new AsyncCallbackWrapper<boolean>(callback);
    taskpool.execute((): void =>{
      nativeEqual(agent, otherAgent, myCall);
    });
  }
  export function equal(agent: WantAgent, otherAgent: WantAgent): Promise<boolean> {
    return new Promise<boolean>((resolve: (data:boolean)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<boolean>((err: BusinessError<void>, data: boolean)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
      nativeEqual(agent, otherAgent, myCall);
    });
    });
  }
  export function getWantAgent(info: WantAgentInfo, callback: AsyncCallback<WantAgent>): void {
    let myCall = new AsyncCallbackWrapper<WantAgent>(callback);
    taskpool.execute((): void =>{
      nativeGetWantAgent(info, myCall);
    });
  }
  export function getWantAgent(info: WantAgentInfo): Promise<WantAgent> {
    return new Promise<WantAgent>((resolve: (data:WantAgent)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<WantAgent>((err: BusinessError<void>, data: WantAgent)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
        nativeGetWantAgent(info, myCall);
      });
    });
  }
  export function getOperationType(agent: WantAgent, callback: AsyncCallback<number>): void {
    let myCall = new AsyncCallbackWrapper<number>(callback);
    taskpool.execute((): void =>{
      nativeGetOperationType(agent, myCall);
    });
  }
  export function getOperationType(agent: WantAgent): Promise<number> {
    return new Promise<number>((resolve: (data:number)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<number>((err: BusinessError<void>, data: number)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void =>{
        nativeGetOperationType(agent, myCall);
    });
    });
  }

  export enum WantAgentFlags {
    ONE_TIME_FLAG = 0,
    NO_BUILD_FLAG,
    CANCEL_PRESENT_FLAG,
    UPDATE_PRESENT_FLAG,
    CONSTANT_FLAG,
    REPLACE_ELEMENT,
    REPLACE_ACTION,
    REPLACE_URI,
    REPLACE_ENTITIES,
    REPLACE_BUNDLE
  }
  export enum OperationType {
    UNKNOWN_TYPE = 0,
    START_ABILITY,
    START_ABILITIES,
    START_SERVICE,
    SEND_COMMON_EVENT,
    START_SERVICE_EXTENSION = 6
  }
  export interface CompleteData {
    info: WantAgent;
    want: Want;
    finalCode: number;
    finalData: string;
    extraInfo?: Record<string, Object>;
  }

  class CompleteDataImpl implements CompleteData {
    public info: WantAgent;
    public want: Want;
    public finalCode: number;
    public finalData: string;
    public extraInfo?: Record<string, Object>;
  }

  export type TriggerInfo = _TriggerInfo;
  export type WantAgentInfo = _WantAgentInfo;
}
export type WantAgent = object;
export default wantAgent;
