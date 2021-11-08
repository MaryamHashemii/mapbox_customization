# mapbox_customization
if you want to make custom the mapbox map platform with your map style and tiles that you made it before and now get the response, I can lead you to do that!
1.get the maapboxsdk from its repository,notice that it should be version 9.7.0
2.edit the HttpRequestImpl.java file like the above file.
3.the you should add libraryGroupId and libraryVersion in your gradle of mapboxsdk(app level) and finally add artifactorypublish and now you can publish your own customized sdk on your repository and using it in your project by add to dependency..

hope this trick be usefull for you.
if you have any problem or question ask in issue section, i will respond them as soon as i see..
