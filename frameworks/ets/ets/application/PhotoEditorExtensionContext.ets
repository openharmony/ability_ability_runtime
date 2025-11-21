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


import Want from '@ohos.app.ability.Want';
import image from '@ohos.multimedia.image';
import { AbilityResult } from 'ability.abilityResult';
import { AsyncCallback } from '@ohos.base';
import { BusinessError } from '@ohos.base';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import ExtensionContext from 'application.ExtensionContext';


class Cleaner {
  static callback(cleaner: Cleaner): void {
      cleaner.clean()
  }
  constructor(targetPtr: long) {
      this.targetPtr = targetPtr
  }
  native clean(): void
  private targetPtr: long = 0
}

export function callback(cleaner: Cleaner): void {
  cleaner.clean();
}

let destroyRegister = new FinalizationRegistry<Cleaner>(Cleaner.callback)
let unregisterToken = new object()

export default class PhotoEditorExtensionContext extends ExtensionContext {
  nativeExtensionContext:long = 0;
  private cleaner: Cleaner | null = null;
  registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
      destroyRegister.register(this, this.cleaner!, unregisterToken);
  }
  unregisterCleaner(): void {
      destroyRegister.unregister(unregisterToken);
  }
  constructor(context:long) {
    if(this.nativeExtensionContext == 0){
          this.nativeExtensionContext = context;
    }
    this.registerCleaner(this.nativeExtensionContext)
  }

  private native nativeSaveEditedContentWithUri(uri: string, callback: AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeSaveEditedContentWithImage(image: image.PixelMap, options: image.PackingOption,
    callback: AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeSaveWithUriCheck(uri: string): void;
  private native nativeSaveWithImageCheck(image: image.PixelMap, options: image.PackingOption): void;

  saveEditedContentWithUri(uri: string): Promise<AbilityResult> {
    this.nativeSaveWithUriCheck(uri);
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult) => void,
    reject: (err: BusinessError) => void): void => {
      let myCall =
        new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as AbilityResult);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeSaveEditedContentWithUri(uri, myCall);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
      return p;
  }

  saveEditedContentWithImage(image: image.PixelMap, options: image.PackingOption): Promise<AbilityResult> {
    this.nativeSaveWithImageCheck(image, options);
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult) => void,
    reject: (err: BusinessError) => void): void => {
      let myCall =
        new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as AbilityResult);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeSaveEditedContentWithImage(image, options, myCall);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}
