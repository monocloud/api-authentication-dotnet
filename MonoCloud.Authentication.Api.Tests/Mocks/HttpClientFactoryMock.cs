namespace MonoCloud.Authentication.Api.Tests.Mocks;

public class HttpClientFactoryMock : IHttpClientFactory
{
  public HttpClient CreateClient(string name)
  {
    return new HttpClient();
  }
}
