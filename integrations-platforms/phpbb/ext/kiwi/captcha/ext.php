<?php
/**
 * The extension enable check: phpBB 3.3 and PHP 7.4 are the floor.
 */

class kiwi_captcha_ext
{
    /**
     * @param string $mode enable|disable|purge
     *
     * @return bool
     */
    public function is_enableable()
    {
        return PHP_VERSION_ID >= 70400;
    }
}
