import {AbilityConstant} from '@ohos.app.ability.AbilityConstant';
import {Want} from '@ohos.app.ability.Want';
import {UIExtensionContentSession} from 'UIExtensionContentSession';
import {UIExtensionContext} from '../../uiextensioncontext/ets/UIExtensionContext';

class ExtensionAbility {}

export default class UIExtensionAbility extends ExtensionAbility {

  uiExtenstionContext?: UIExtensionContext;

  onCreate(launchParam: AbilityConstant.LaunchParam): void {}

  onSessionCreate(want: Want, session: UIExtensionContentSession): void {}

  onSessionDestroy(session: UIExtensionContentSession): void {}

  onForeground(): void {}

  onBackground(): void {}

  //onDestroy(): void | Promise<void>;
  onDestroy(): void {}
}
