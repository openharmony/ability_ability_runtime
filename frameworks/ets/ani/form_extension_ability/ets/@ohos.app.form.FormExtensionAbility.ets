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

import formBindingData from '@ohos.app.form.formBindingData';
import FormExtensionContext from './application/FormExtensionContext';
import Want from '@ohos.app.ability.Want';

type OnStopFn = () => void;

export default class FormExtensionAbility {
  public context: FormExtensionContext = new FormExtensionContext();

  onAddForm(want: Want): formBindingData.FormBindingData {
    console.log('FormExtensionAbility onAddForm');
    let dataObj1: Record<string, string> = {
      'temperature': '11c',
      'time': '11:00'
    };

    let obj1: formBindingData.FormBindingData = formBindingData.createFormBindingData(dataObj1);
    return obj1;
  }

  onCastToNormalForm(formId: string): void {
    console.log(`FormExtensionAbility onCastToNormalForm, formId: ${formId}`);
  }

  onUpdateForm(formId: string, wantParams?: Record<string, Object>): void {
    console.log(`FormExtensionAbility onUpdateForm, formId: ${formId},
        wantPara: ${wantParams?.['ohos.extra.param.key.host_bg_inverse_color']}`);
  }

  onChangeFormVisibility(newStatus: Record<string, number>): void {
    console.log(`FormExtensionAbility onChangeFormVisibility, newStatus: ${newStatus}`);
  }

  onFormEvent(formId: string, message: string): void {
    console.log(`FormExtensionAbility onFormEvent, formId: ${formId}, message: ${message}`);
  }

  onRemoveForm(formId: string): void {
    console.log(`FormExtensionAbility onRemoveForm, formId: ${formId}`);
  }
  
  onStop?: OnStopFn;
}