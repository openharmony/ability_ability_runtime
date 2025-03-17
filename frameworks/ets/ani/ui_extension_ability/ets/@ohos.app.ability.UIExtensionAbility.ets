import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import Want from '@ohos.app.ability.Want';
import UIExtensionContentSession from './@ohos.app.ability.UIExtensionContentSession';
//import UIExtensionContext from 'application.UIExtensionContext';
import UIExtensionContext from './application/UIExtensionContext';

class ExtensionAbility{}

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
