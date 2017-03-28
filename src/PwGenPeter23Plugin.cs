/*
    Yaroslav Veremenko <yaroslav@veremenko.inf> (c) 2017
    Based on code of:
    Peter <i@peter23.com> 2011  http://genpas.peter23.com/
    KATO Kazuyoshi <kzys@8-p.info>  http://8-p.info/pwgen/
    Frank4DD  http://www.frank4dd.com/howto/various/pwgen.htm
 
    This program is a C# port of pwgen.
    The original C source code written by Theodore Ts'o.
    <http://sourceforge.net/projects/pwgen/>
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

using KeePass.Plugins;

namespace YvPwGenPeter23
{
    public sealed class YvPwGenPeter23Ext : Plugin
    {
        private IPluginHost host;
        private Generator generator;

        public override bool Initialize(IPluginHost pluginHost)
        {
            if (pluginHost == null)
            {
                return false;
            }

            host = pluginHost;
            generator = new Generator();
            pluginHost.PwGeneratorPool.Add(generator);

            return true;
        }

        public override void Terminate()
        {
            if (host != null)
            {
                host.PwGeneratorPool.Remove(generator.Uuid);
                generator = null;
                host = null;
            }
        }
    }
}
