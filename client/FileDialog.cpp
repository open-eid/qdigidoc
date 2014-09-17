/*
 * QDigiDocClient
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "FileDialog.h"

#include <common/Settings.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QTemporaryFile>
#include <QtGui/QDesktopServices>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#else
#include <QtGui/QMessageBox>
#endif
#ifdef Q_OS_WIN
#include <QtCore/QLibrary>
#include <Shobjidl.h>
#include <Shlguid.h>
#endif

FileDialog::FileDialog( QWidget *parent )
:	QFileDialog( parent )
{
}

FileDialog::Options FileDialog::addOptions()
{
	if( qApp->arguments().contains( "-noNativeFileDialog" ) )
		return DontUseNativeDialog;
	return 0;
}

bool FileDialog::fileIsWritable( const QString &filename )
{
	QFile f( filename );
	bool remove = !f.exists();
	bool result = f.open( QFile::WriteOnly|QFile::Append );
	if( remove )
		f.remove();
	return result;
}

QString FileDialog::fileSize( quint64 bytes )
{
	const quint64 kb = 1024;
	const quint64 mb = 1024 * kb;
	const quint64 gb = 1024 * mb;
	const quint64 tb = 1024 * gb;
	if( bytes >= tb )
		return QString( "%1 TB" ).arg( qreal(bytes) / tb, 0, 'f', 3 );
	if( bytes >= gb )
		return QString( "%1 GB" ).arg( qreal(bytes) / gb, 0, 'f', 2 );
	if( bytes >= mb )
		return QString( "%1 MB" ).arg( qreal(bytes) / mb, 0, 'f', 1 );
	if( bytes >= kb )
		return QString( "%1 KB" ).arg( bytes / kb );
	return QString( "%1 B" ).arg( bytes );
}

QString FileDialog::getDir( const QString &dir )
{
	return !dir.isEmpty() ? dir : Settings(qApp->applicationName()).value("lastPath",
		QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation)).toString();
}

QString FileDialog::getOpenFileName( QWidget *parent, const QString &caption,
	const QString &dir, const QString &filter, QString *selectedFilter, Options options )
{
	return result( QFileDialog::getOpenFileName( parent,
		caption, getDir( dir ), filter, selectedFilter, options|addOptions() ) );
}

QStringList FileDialog::getOpenFileNames( QWidget *parent, const QString &caption,
	const QString &dir, const QString &filter, QString *selectedFilter, Options options )
{
	return result( QFileDialog::getOpenFileNames( parent,
		caption, getDir( dir ), filter, selectedFilter,
#ifdef Q_OS_WIN
		DontResolveSymlinks|options|addOptions() ) );
#else
		options|addOptions() ) );
#endif
}

QString FileDialog::getExistingDirectory( QWidget *parent, const QString &caption,
	const QString &dir, Options options )
{
	QString res;
#ifdef Q_OS_WIN
	if( QSysInfo::windowsVersion() >= QSysInfo::WV_VISTA )
	{
		IFileOpenDialog *pfd = 0;
		CoCreateInstance( CLSID_FileOpenDialog, NULL, CLSCTX_INPROC, IID_PPV_ARGS(&pfd) );
		pfd->SetOptions( FOS_PICKFOLDERS );
		QString dest = QDir::toNativeSeparators( getDir( dir ) );
		if( !dest.isEmpty() )
		{
			typedef HRESULT (WINAPI *PtrParsingName)(PCWSTR pszPath, IBindCtx *pbc, REFIID riid, void **ppv);
			QLibrary lib("shell32");
			IShellItem *folder = 0;
			PtrParsingName p = PtrParsingName(lib.resolve("SHCreateItemFromParsingName"));
			if( p && SUCCEEDED(p( LPCWSTR(dest.utf16()), 0, IID_PPV_ARGS(&folder) )) )
			{
				pfd->SetFolder(folder);
				folder->Release();
			}
		}
		if( !caption.isEmpty() )
			pfd->SetTitle( LPCWSTR(caption.utf16()) );
		if( SUCCEEDED(pfd->Show( parent && parent->window() ? HWND(parent->window()->winId()) : 0 )) )
		{
			IShellItem *item = 0;
			if( SUCCEEDED(pfd->GetResult( &item )) )
			{
				LPWSTR path = 0;
				if( SUCCEEDED(item->GetDisplayName( SIGDN_FILESYSPATH, &path )) )
				{
					res = QString( (QChar*)path );
					CoTaskMemFree( path );
				}
				else
				{
					// Case it is Libraries/Favorites
					IEnumShellItems *items = 0;
					if( SUCCEEDED(item->BindToHandler( 0, BHID_EnumItems, IID_PPV_ARGS(&items) )) )
					{
						IShellItem *list = 0;
						if( items->Next( 1, &list, 0 ) == NOERROR )
						{
							LPWSTR path = 0;
							if( SUCCEEDED(list->GetDisplayName( SIGDN_FILESYSPATH, &path )) )
							{
								res = QFileInfo( QString( (QChar*)path ) + "/.." ).absoluteFilePath();
								CoTaskMemFree( path );
							}
							list->Release();
						}
						items->Release();
					}
				}
			}
			item->Release();
		}
		pfd->Release();
	}
	else
#endif
	res = QFileDialog::getExistingDirectory( parent,
		caption, getDir( dir ), ShowDirsOnly|options|addOptions() );
#ifdef Q_OS_WIN
	if( !QTemporaryFile( res + "/.XXXXXX" ).open() )
#else
	if( !QFileInfo( res ).isWritable() )
#endif
	{
		QMessageBox::warning( parent, caption,
			tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( res ) );
		return QString();
	}

	return result( res );
}

QString FileDialog::getSaveFileName( QWidget *parent, const QString &caption,
	const QString &dir, const QString &filter, QString *selectedFilter, Options options )
{
	QString file;
	while( true )
	{
		file =  QFileDialog::getSaveFileName( parent,
			caption, getDir( dir ), filter, selectedFilter, options|addOptions() );
		if( !file.isEmpty() && !fileIsWritable( file ) )
		{
			QMessageBox::warning( parent, caption,
				tr( "You don't have sufficient privileges to write this file into folder %1" ).arg( file ) );
		}
		else
			break;
	}
	return result( file );
}

QString FileDialog::result( const QString &str )
{
	if(!str.isEmpty())
		Settings(qApp->applicationName()).setValue("lastPath", QFileInfo(str).absolutePath());
	return str;
}

QStringList FileDialog::result( const QStringList &list )
{
	QStringList l;
	Q_FOREACH( const QString &str, list )
		l << result( str );
	return l;
}
