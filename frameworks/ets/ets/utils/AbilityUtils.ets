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
import { BusinessError, AsyncCallback } from '@ohos.base';
import hilog from '@ohos.hilog'

const DOMAIN_ID = 0xD001300;
const TAG = 'AbilityUtils';
const LEVEL = 100;

export default class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

export class AbilityUtils {
  public static getClassType(obj: Object): ClassType | undefined {
    try {
      let type = Type.of(obj);
      return type as ClassType;
    } catch (err) {
      hilog.error(DOMAIN_ID, TAG, `getClassType error: ${err}`);
      return undefined;
    }
  }

  public static isOverride(type: ClassType, methodName: string, stopBaseClassType: ClassType): boolean | undefined {
    let currType = type;
    let level = 0;
    while (!currType.equals(stopBaseClassType)) {
      try {
        for (let methodIdx = 0; methodIdx < currType.getMethodsNum(); methodIdx++) {
          const method = currType.getMethod(methodIdx)
          if (method.getName().equals(methodName)) {
            if (!method.isInherited()) {
              return true;
            }
          }
        }
        let baseType = currType.getBaseType();
        if (baseType.equals(currType)) {
          hilog.error(DOMAIN_ID, TAG, `isOverride: baseType equals currType (${currType.getName()})`);
          return undefined;
        }
        level++;
        if (level >= LEVEL) {
          hilog.error(DOMAIN_ID, TAG, `isOverride: inheritance level >= ${LEVEL}, abort`);
          return undefined;
        }
        currType = baseType;
      } catch (err) {
        hilog.error(DOMAIN_ID, TAG, `isOverride error: ${err}`);
        return undefined;
      }
    }
    return false;
  }
}
